// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
// Assertions for alert sender/receiver pair for the asynchronous case.
// Intended to use with a formal tool.

`include "prim_assert.sv"

module prim_alert_rxtx_async_assert_fpv
  import prim_mubi_pkg::mubi4_t;
(
  input        clk_i,
  input        rst_ni,
  // for sigint error and skew injection only
  input        ping_err_pi,
  input        ping_err_ni,
  input [1:0]  ping_skew_i,
  input        ack_err_pi,
  input        ack_err_ni,
  input [1:0]  ack_skew_i,
  input        alert_err_pi,
  input        alert_err_ni,
  input [1:0]  alert_skew_i,
  // normal I/Os
  input        alert_test_i,
  input  mubi4_t init_trig_i,
  input        alert_req_i,
  input        alert_ack_o,
  input        alert_state_o,
  input        ping_req_i,
  input        ping_ok_o,
  input        integ_fail_o,
  input        alert_o
);

  import prim_mubi_pkg::mubi4_test_true_strict;

  logic error_present;
  assign error_present = ping_err_pi  | ping_err_ni |
                         ack_err_pi   | ack_err_ni  |
                         alert_err_pi | alert_err_ni;

  logic init_pending;
  assign init_pending = mubi4_test_true_strict(init_trig_i) ||
                        prim_alert_rxtx_async_tb.i_prim_alert_receiver.state_q inside {
                        prim_alert_rxtx_async_tb.i_prim_alert_receiver.InitReq,
                        prim_alert_rxtx_async_tb.i_prim_alert_receiver.InitAckWait};

  logic sender_is_idle, receiver_is_idle, sender_is_pinging;
  assign sender_is_idle = i_prim_alert_sender.state_q == i_prim_alert_sender.Idle;
  assign receiver_is_idle = i_prim_alert_receiver.state_q == i_prim_alert_receiver.Idle;
  assign sender_is_pinging = i_prim_alert_sender.state_q inside
                             {i_prim_alert_sender.PingHsPhase1, i_prim_alert_sender.PingHsPhase2};

  // A signal that is true if the alert sender is sending an alert (p & !n)
  logic alert_from_sender;
  assign alert_from_sender = prim_alert_rxtx_async_tb.alert_tx_out.alert_p &&
                             !prim_alert_rxtx_async_tb.alert_tx_out.alert_n;

  // used to check that an error has never occurred so far
  // this is used to check the handshake below. the handshake can lock up
  // the protocol FSMs causing the handshake to never complete.
  // note that this will block any ping messages and hence it can be
  // eventually detected by the alert handler.
  logic error_setreg_d, error_setreg_q;
  assign error_setreg_d = error_present | error_setreg_q;

  always_ff @(posedge clk_i or negedge rst_ni) begin : p_reg
    if (!rst_ni) begin
      error_setreg_q <= 1'b0;
    end else begin
      error_setreg_q <= error_setreg_d;
    end
  end

  // Note: we can only detect sigint errors where one wire is flipped.
  `ASSUME_FPV(PingErrorsAreOH_M,  $onehot0({ping_err_pi, ping_err_ni})  )
  `ASSUME_FPV(AckErrorsAreOH_M,   $onehot0({ack_err_pi, ack_err_ni})    )
  `ASSUME_FPV(AlertErrorsAreOH_M, $onehot0({alert_err_pi, alert_err_ni}))

  // ping will stay high until ping ok received, then it must be deasserted
  // TODO: this excludes the case where no ping ok will be returned due to an error
  `ASSUME_FPV(PingDeassert_M, ping_req_i && ping_ok_o |=> !ping_req_i)
  `ASSUME_FPV(PingEn_M, $rose(ping_req_i) |-> ping_req_i throughout
      (ping_ok_o || error_present)[->1] ##1 $fell(ping_req_i))

  // Note: the sequence lengths of the handshake and the following properties needs to
  // be parameterized accordingly if different clock ratios are to be used here.
  // TODO: tighten bounds if possible
  sequence FullHandshake_S;
    $rose(prim_alert_rxtx_async_tb.alert_pd)   ##[3:6]
    $rose(prim_alert_rxtx_async_tb.ack_pd)     &&
    $stable(prim_alert_rxtx_async_tb.alert_pd) ##[3:6]
    $fell(prim_alert_rxtx_async_tb.alert_pd)   &&
    $stable(prim_alert_rxtx_async_tb.ack_pd)   ##[3:6]
    $fell(prim_alert_rxtx_async_tb.ack_pd)     &&
    $stable(prim_alert_rxtx_async_tb.alert_pd);
  endsequence

  // note: injected errors may lockup the FSMs, and hence the full HS can
  // only take place if both FSMs are in a good state
  `ASSERT(PingHs_A, ##1 $changed(prim_alert_rxtx_async_tb.ping_pd) &&
      sender_is_idle && receiver_is_idle |-> ##[0:5] FullHandshake_S,
      clk_i, !rst_ni || error_setreg_q || init_pending)
  `ASSERT(AlertHs_A, alert_req_i &&
      sender_is_idle && receiver_is_idle |-> ##[0:5] FullHandshake_S,
      clk_i, !rst_ni || error_setreg_q || init_pending)
  `ASSERT(AlertTestHs_A, alert_test_i &&
      sender_is_idle && receiver_is_idle |-> ##[0:5] FullHandshake_S,
      clk_i, !rst_ni || error_setreg_q || init_pending)
  // Make sure we eventually get an ACK
  `ASSERT(AlertReqAck_A, alert_req_i &&
      sender_is_idle && receiver_is_idle |-> strong(##[1:$] alert_ack_o),
      clk_i, !rst_ni || error_setreg_q || init_pending)

  // Transmission of pings
  //
  // Check that if we tell the receiver to request a ping then it will send one and get a response
  // in a bounded time.
  //
  // This bound is relatively large as in the worst case, we need to resolve staggered differential
  // signal patterns on all three differential channels.
  //
  // Note 1: The complete transmission of pings only happens when no ping handshake is in progress,
  // so we only allow the property to start when the sender isn't in a ping handshake FSM state.
  //
  // Note 2: The receiver gives up on a ping request if it receives an alert (this is strong
  // evidence that alerts can come through, so it doesn't really need to do the ping at all!) To see
  // the ping handshake go through, we constrain things to ensure this doesn't happen.
  `ASSERT(AlertPingOk_A,
          !sender_is_pinging && $rose(ping_req_i) |-> ##[1:23] ping_ok_o,
          clk_i,
          (!rst_ni || error_setreg_q || init_pending || alert_from_sender))

  `ASSERT(AlertPingIgnored_A,
          sender_is_pinging && $rose(ping_req_i) |-> ping_ok_o == 0 throughout ping_req_i[->1],
          clk_i, !rst_ni || error_setreg_q)

  // transmission of first alert assertion (no ping collision)
  `ASSERT(AlertCheck0_A,
      !ping_req_i [*10] ##1 ($rose(alert_req_i) || $rose(alert_test_i)) && sender_is_idle |->
      ##[3:5] alert_o,
      clk_i, !rst_ni || ping_req_i || error_setreg_q || init_pending || alert_skew_i || ack_skew_i)
  // eventual transmission of alerts in the general case which can include continous ping
  // collisions
  `ASSERT(AlertCheck1_A,
      alert_req_i || alert_test_i |-> strong(##[1:$] sender_is_idle ##[3:5] alert_o),
      clk_i, !rst_ni || error_setreg_q ||
      prim_alert_rxtx_async_tb.i_prim_alert_sender.alert_clr || init_pending)

  // basic liveness of FSMs in case no errors are present
  `ASSERT(FsmLivenessSender_A,
      !error_present [*2] ##1 !error_present && !sender_is_idle |->
      strong(##[1:$] sender_is_idle),
      clk_i, !rst_ni || error_present || init_pending)
  `ASSERT(FsmLivenessReceiver_A,
      !error_present [*2] ##1 !error_present && receiver_is_idle |->
      strong(##[1:$] receiver_is_idle),
      clk_i, !rst_ni || error_present || init_pending)

  // check that the in-band reset moves sender FSM into Idle state.
  `ASSERT(InBandInitFromReceiverToSender_A,
      mubi4_test_true_strict(init_trig_i)
      |->
      ##[1:30] sender_is_idle,
      clk_i, !rst_ni || error_present)

endmodule : prim_alert_rxtx_async_assert_fpv
