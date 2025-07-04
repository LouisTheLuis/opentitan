// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
// Description: CSRNG command staging module.
//

module csrng_cmd_stage import csrng_pkg::*; #(
  parameter int CmdFifoWidth = 32,
  parameter int CmdFifoDepth = 16,
  parameter int StateId = 4
) (
  input logic                        clk_i,
  input logic                        rst_ni,
  // Command input.
  input logic                        cs_enable_i,
  input logic                        cmd_stage_vld_i,
  input logic [StateId-1:0]          cmd_stage_shid_i,
  input logic [CmdFifoWidth-1:0]     cmd_stage_bus_i,
  output logic                       cmd_stage_rdy_o,
  // Command checking interface.
  input logic                        reseed_cnt_reached_i,
  output logic                       reseed_cnt_alert_o,
  output logic                       invalid_cmd_seq_alert_o,
  output logic                       invalid_acmd_alert_o,
  // Command to arbiter.
  output logic                       cmd_arb_req_o,
  output logic                       cmd_arb_sop_o,
  output logic                       cmd_arb_mop_o,
  output logic                       cmd_arb_eop_o,
  input logic                        cmd_arb_gnt_i,
  output logic [CmdFifoWidth-1:0]    cmd_arb_bus_o,
  // Ack from core.
  input logic                        cmd_ack_i,
  input csrng_cmd_sts_e              cmd_ack_sts_i,
  // Ack to app i/f.
  output logic                       cmd_stage_ack_o,
  output csrng_cmd_sts_e             cmd_stage_ack_sts_o,
  // Genbits from core.
  input logic                        genbits_vld_i,
  input logic [127:0]                genbits_bus_i,
  input logic                        genbits_fips_i,
  // Genbits to app i/f.
  output logic                       genbits_vld_o,
  input logic                        genbits_rdy_i,
  output logic [127:0]               genbits_bus_o,
  output logic                       genbits_fips_o,
  // Error indication.
  output logic [2:0]                 cmd_stage_sfifo_cmd_err_o,
  output logic [2:0]                 cmd_stage_sfifo_genbits_err_o,
  output logic                       cmd_gen_cnt_err_o,
  output logic                       cmd_stage_sm_err_o
);

  // Genbits parameters.
  localparam int GenBitsFifoWidth = 1+128;
  localparam int GenBitsFifoDepth = 1;
  localparam int GenBitsCntrWidth = 12;

  // Command FIFO.
  logic [CmdFifoWidth-1:0] sfifo_cmd_rdata;
  logic [$clog2(CmdFifoDepth):0] sfifo_cmd_depth;
  logic                    sfifo_cmd_push;
  logic [CmdFifoWidth-1:0] sfifo_cmd_wdata;
  logic                    sfifo_cmd_pop;
  logic [2:0]              sfifo_cmd_err;
  logic                    sfifo_cmd_full;
  logic                    sfifo_cmd_not_empty;

  // Genbits FIFO.
  logic [GenBitsFifoWidth-1:0] sfifo_genbits_rdata;
  logic                        sfifo_genbits_push;
  logic [GenBitsFifoWidth-1:0] sfifo_genbits_wdata;
  logic                        sfifo_genbits_pop;
  logic [2:0]                  sfifo_genbits_err;
  logic                        sfifo_genbits_full;
  logic                        sfifo_genbits_not_empty;

  // Command signals.
  logic [3:0]                  cmd_len;
  logic                        cmd_fifo_zero;
  logic                        cmd_fifo_pop;
  logic                        cmd_len_dec;
  logic                        cmd_gen_cnt_dec;
  logic                        cmd_gen_1st_req;
  logic                        cmd_gen_inc_req;
  logic                        cmd_gen_cnt_last;
  logic                        cmd_final_ack;
  logic                        cmd_err_ack;
  logic [GenBitsCntrWidth-1:0] cmd_gen_cnt;
  csrng_cmd_sts_e              err_sts;
  logic                        reseed_cnt_exceeded;
  logic                        invalid_cmd_seq;
  logic                        invalid_acmd;
  logic [2:0]                  acmd;

  // Flops.
  logic                    cmd_ack_q, cmd_ack_d;
  csrng_cmd_sts_e          cmd_ack_sts_q, cmd_ack_sts_d;
  logic [3:0]              cmd_len_q, cmd_len_d;
  logic                    cmd_gen_flag_q, cmd_gen_flag_d;
  logic [11:0]             cmd_gen_cmd_q, cmd_gen_cmd_d;
  logic                    instantiated_d, instantiated_q;

  logic                    local_escalate;


  always_ff @(posedge clk_i or negedge rst_ni)
    if (!rst_ni) begin
      cmd_ack_q       <= '0;
      cmd_ack_sts_q   <= CMD_STS_SUCCESS;
      cmd_len_q       <= '0;
      cmd_gen_flag_q  <= '0;
      cmd_gen_cmd_q   <= '0;
      instantiated_q  <= '0;
    end else begin
      cmd_ack_q       <= cmd_ack_d;
      cmd_ack_sts_q   <= cmd_ack_sts_d;
      cmd_len_q       <= cmd_len_d;
      cmd_gen_flag_q  <= cmd_gen_flag_d;
      cmd_gen_cmd_q   <= cmd_gen_cmd_d;
      instantiated_q  <= instantiated_d;
    end

  assign  cmd_stage_sfifo_cmd_err_o = sfifo_cmd_err;
  assign  cmd_stage_sfifo_genbits_err_o = sfifo_genbits_err;

  //---------------------------------------------------------
  // Capture the transfer length of data behind the command.
  //---------------------------------------------------------

  prim_fifo_sync #(
    .Width(CmdFifoWidth),
    .Pass(0),
    .Depth(CmdFifoDepth),
    .OutputZeroIfEmpty(1'b0)
  ) u_prim_fifo_cmd (
    .clk_i          (clk_i),
    .rst_ni         (rst_ni),
    .clr_i          (!cs_enable_i),
    .wvalid_i       (sfifo_cmd_push),
    .wready_o       (),
    .wdata_i        (sfifo_cmd_wdata),
    .rvalid_o       (sfifo_cmd_not_empty),
    .rready_i       (sfifo_cmd_pop),
    .rdata_o        (sfifo_cmd_rdata),
    .full_o         (sfifo_cmd_full),
    .depth_o        (sfifo_cmd_depth),
    .err_o          ()
  );

  assign sfifo_cmd_wdata = cmd_stage_bus_i;

  assign sfifo_cmd_push = cs_enable_i && cmd_stage_rdy_o && cmd_stage_vld_i;

  assign sfifo_cmd_pop = cs_enable_i && cmd_fifo_pop;

  assign cmd_arb_bus_o =
         cmd_gen_inc_req ? {15'b0,cmd_gen_cnt_last,cmd_stage_shid_i,cmd_gen_cmd_q} :
        // pad,glast,id,f,clen,cmd
        cmd_gen_1st_req ? {15'b0,cmd_gen_cnt_last,cmd_stage_shid_i,sfifo_cmd_rdata[11:0]} :
        cmd_arb_mop_o   ? sfifo_cmd_rdata :
        '0;

  assign cmd_stage_rdy_o = !sfifo_cmd_full;

  assign sfifo_cmd_err =
         {(sfifo_cmd_push && sfifo_cmd_full),
          (sfifo_cmd_pop && !sfifo_cmd_not_empty),
          (sfifo_cmd_full && !sfifo_cmd_not_empty)};


  // State machine controls.
  assign cmd_fifo_zero = (sfifo_cmd_depth == '0);
  assign cmd_len = sfifo_cmd_rdata[7:4];

  // Capture the length of csrng command.
  assign cmd_len_d =
         (!cs_enable_i) ? '0 :
         cmd_arb_sop_o ? cmd_len :
         cmd_len_dec ? (cmd_len_q-1) :
         cmd_len_q;

  // Capture the application command type.
  assign acmd = sfifo_cmd_rdata[2:0];

  // For gen commands, capture information from the original command for use later.
  assign cmd_gen_flag_d =
         (!cs_enable_i) ? '0 :
         cmd_gen_1st_req ? (acmd == GEN) :
         cmd_gen_flag_q;

  assign cmd_gen_cmd_d =
         (!cs_enable_i) ? '0 :
         cmd_gen_1st_req ? {sfifo_cmd_rdata[11:0]} :
         cmd_gen_cmd_q;

  // SEC_CM: GEN_CMD.CTR.REDUN
  prim_count #(
    .Width(GenBitsCntrWidth),
    .ResetValue({GenBitsCntrWidth{1'b1}})
  ) u_prim_count_cmd_gen_cntr (
    .clk_i,
    .rst_ni,
    .clr_i(!cs_enable_i),
    .set_i(cmd_gen_1st_req),
    .set_cnt_i(sfifo_cmd_rdata[12+:GenBitsCntrWidth]),
    .incr_en_i(1'b0),
    .decr_en_i(cmd_gen_cnt_dec), // Count down.
    .step_i(GenBitsCntrWidth'(1)),
    .commit_i(1'b1),
    .cnt_o(cmd_gen_cnt),
    .cnt_after_commit_o(),
    .err_o(cmd_gen_cnt_err_o)
  );

  // For naming consistency.
  assign local_escalate = cmd_gen_cnt_err_o;

  //---------------------------------------------------------
  // state machine to process command
  //---------------------------------------------------------
  // Encoding generated with:
  // $ ./util/design/sparse-fsm-encode.py -d 3 -m 11 -n 8 \
  //     -s 170131814 --language=sv
  //
  // Hamming distance histogram:
  //
  //  0: --
  //  1: --
  //  2: --
  //  3: |||||||||||| (21.82%)
  //  4: |||||||||||||||||||| (36.36%)
  //  5: ||||||||||||||||| (30.91%)
  //  6: ||||| (9.09%)
  //  7: | (1.82%)
  //  8: --
  //
  // Minimum Hamming distance: 3
  // Maximum Hamming distance: 7
  // Minimum Hamming weight: 1
  // Maximum Hamming weight: 6
  //
  localparam int StateWidth = 8;
  typedef enum logic [StateWidth-1:0] {
    Idle      = 8'b11110101, // idle
    Flush     = 8'b01011011, // flush command FIFO and start over
    ArbGnt    = 8'b00011100, // general arbiter request
    SendSOP   = 8'b00000001, // send sop (start of packet)
    SendMOP   = 8'b01010110, // send mop (middle of packet)
    GenCmdChk = 8'b10001101, // gen cmd check
    CmdAck    = 8'b11000000, // wait for command ack
    GenReq    = 8'b10010011, // process gen requests
    GenArbGnt = 8'b11101110, // generate subsequent arb request
    GenSOP    = 8'b10111010, // generate subsequent request
    Error     = 8'b01100111  // illegal state reached and hang
  } state_e;

  state_e state_d, state_q;
  `PRIM_FLOP_SPARSE_FSM(u_state_regs, state_d, state_q, state_e, Idle)

  always_comb begin
    state_d = state_q;
    cmd_fifo_pop = 1'b0;
    cmd_len_dec = 1'b0;
    cmd_gen_cnt_dec = 1'b0;
    cmd_gen_1st_req = 1'b0;
    cmd_gen_inc_req = 1'b0;
    cmd_gen_cnt_last = 1'b0;
    cmd_final_ack = 1'b0;
    cmd_arb_req_o = 1'b0;
    cmd_arb_sop_o = 1'b0;
    cmd_arb_mop_o = 1'b0;
    cmd_arb_eop_o = 1'b0;
    cmd_stage_sm_err_o = 1'b0;
    cmd_err_ack = 1'b0;
    reseed_cnt_exceeded = 1'b0;
    invalid_cmd_seq = 1'b0;
    invalid_acmd = 1'b0;
    instantiated_d = instantiated_q;

    if (state_q == Error) begin
      // In case we are in the Error state we must ignore the local escalate and enable signals.
      cmd_stage_sm_err_o = 1'b1;
    end else if (local_escalate) begin
      // In case local escalate is high we must transition to the error state.
      state_d = Error;
    end else if (!cs_enable_i && state_q inside {Idle, Flush, ArbGnt, SendSOP, SendMOP, GenCmdChk,
                                                 CmdAck, GenReq, GenArbGnt, GenSOP}) begin
      // In case the module is disabled and we are in a legal state we must go into idle state.
      state_d = Idle;
      instantiated_d = 1'b0;
    end else begin
      // Otherwise do the state machine as normal.
      unique case (state_q)
        Idle: begin
          // Because of the if statement above we won't leave idle if enable is low.
          if (!cmd_fifo_zero) begin
            if (acmd == INS) begin
              if (!instantiated_q) begin
                state_d = ArbGnt;
                instantiated_d = 1'b1;
              end
              if (instantiated_q) begin
                cmd_err_ack = 1'b1;
                invalid_cmd_seq = 1'b1;
                state_d = Idle;
              end
            end else if (acmd == RES) begin
              if (instantiated_q) begin
                state_d = ArbGnt;
              end
              if (!instantiated_q) begin
                cmd_err_ack = 1'b1;
                invalid_cmd_seq = 1'b1;
                state_d = Idle;
              end
            end else if (acmd == GEN) begin
              if (instantiated_q) begin
                // If the issued command is GEN and the reseed count has already been reached,
                // send an ack with an error status response.
                if ((acmd == GEN) && reseed_cnt_reached_i) begin
                  cmd_err_ack = 1'b1;
                  reseed_cnt_exceeded = 1'b1;
                  state_d = Idle;
                end else begin
                  state_d = ArbGnt;
                end
              end
              if (!instantiated_q) begin
                cmd_err_ack = 1'b1;
                invalid_cmd_seq = 1'b1;
                state_d = Idle;
              end
            end else if (acmd == UPD) begin
              if (instantiated_q) begin
                state_d = ArbGnt;
              end
              if (!instantiated_q) begin
                cmd_err_ack = 1'b1;
                invalid_cmd_seq = 1'b1;
                state_d = Idle;
              end
            end else if (acmd == UNI) begin
              // Set the instantiation to zero.
              instantiated_d = 1'b0;
              state_d = ArbGnt;
            end else begin
              // Command was not supported.
              cmd_err_ack = 1'b1;
              invalid_acmd = 1'b1;
              state_d = Idle;
            end
            // If we received an invalid command, pop it from the FIFO. Afterwards, absorb any
            // additional data belonging to the same invalid command and empty the FIFO.
            if (cmd_err_ack) begin
              cmd_fifo_pop = 1'b1;
              state_d = Flush;
            end
          end
        end
        Flush: begin
          // Keep popping the FIFO until it's empty and we're not getting new command input.
          // The decision whether a command is invalid is taken based on the command header but
          // EDN might continue and send additional data belonging to the same command. We have
          // to absorb the full invalid command before we can continue.
          cmd_fifo_pop = sfifo_cmd_not_empty;
          if (!sfifo_cmd_not_empty && !cmd_stage_vld_i) begin
            state_d = Idle;
          end
        end
        ArbGnt: begin
          cmd_arb_req_o = 1'b1;
          if (cmd_arb_gnt_i) begin
            state_d = SendSOP;
          end
        end
        SendSOP: begin
          cmd_gen_1st_req = 1'b1;
          cmd_arb_sop_o = 1'b1;
          cmd_fifo_pop = 1'b1;
          if (sfifo_cmd_rdata[12+:GenBitsCntrWidth] == GenBitsCntrWidth'(1)) begin
            cmd_gen_cnt_last = 1'b1;
          end
          if (cmd_len == '0) begin
            cmd_arb_eop_o = 1'b1;
            state_d = GenCmdChk;
          end else begin
            state_d = SendMOP;
          end
        end
        SendMOP: begin
          if (!cmd_fifo_zero) begin
            cmd_fifo_pop = 1'b1;
            cmd_len_dec = 1'b1;
            if (cmd_len_q == 4'h1) begin
              cmd_arb_mop_o = 1'b1;
              cmd_arb_eop_o = 1'b1;
              state_d = GenCmdChk;
            end else begin
              cmd_arb_mop_o = 1'b1;
            end
          end
        end
        GenCmdChk: begin
          if (cmd_gen_flag_q) begin
            cmd_gen_cnt_dec = 1'b1;
          end
          state_d = CmdAck;
        end
        CmdAck: begin
          if (cmd_ack_i) begin
            // The state database has successfully been updated.
            // In case of Generate commands, we get the generated bits one clock cycle before
            // receiving the ACK from the state database (from csrng_ctr_drbg_gen).
            state_d = GenReq;
          end
        end
        GenReq: begin
          // Flag set if a gen request.
          if (cmd_gen_flag_q) begin
            // Must stall if genbits fifo is not clear.
            if (!sfifo_genbits_full) begin
              if (cmd_gen_cnt == '0) begin
                cmd_final_ack = 1'b1;
                state_d = Idle;
              end else begin
                // Issue a subsequent gen request.
                state_d = GenArbGnt;
              end
            end
          end else begin
            // Ack for the non-gen request case.
            cmd_final_ack = 1'b1;
            state_d = Idle;
          end
        end
        GenArbGnt: begin
          cmd_arb_req_o = 1'b1;
          if (cmd_arb_gnt_i) begin
            state_d = GenSOP;
          end
        end
        GenSOP: begin
          cmd_arb_sop_o = 1'b1;
          cmd_arb_eop_o = 1'b1;
          cmd_gen_inc_req = 1'b1;
          state_d = GenCmdChk;
          // Check for final genbits beat.
          if (cmd_gen_cnt == GenBitsCntrWidth'(1)) begin
            cmd_gen_cnt_last = 1'b1;
          end
        end
        // Error: The error state is now covered by the if statement above.
        default: begin
          state_d = Error;
          cmd_stage_sm_err_o = 1'b1;
        end
      endcase // unique case (state_q)
    end
  end

  //---------------------------------------------------------
  // Genbits FIFO.
  //---------------------------------------------------------

  prim_fifo_sync #(
    .Width(GenBitsFifoWidth),
    .Pass(0),
    .Depth(GenBitsFifoDepth),
    .OutputZeroIfEmpty(0) // Set to 0, and let last data drive out.
  ) u_prim_fifo_genbits (
    .clk_i          (clk_i),
    .rst_ni         (rst_ni),
    .clr_i          (!cs_enable_i),
    .wvalid_i       (sfifo_genbits_push),
    .wready_o       (),
    .wdata_i        (sfifo_genbits_wdata),
    .rvalid_o       (sfifo_genbits_not_empty),
    .rready_i       (sfifo_genbits_pop),
    .rdata_o        (sfifo_genbits_rdata),
    .full_o         (sfifo_genbits_full),
    .depth_o        (), // sfifo_genbits_depth)
    .err_o          ()
  );

  assign sfifo_genbits_wdata = {genbits_fips_i,genbits_bus_i};

  // The prim_fifo_sync primitive is constructed to only accept pushes if there is indeed space
  // available. Backpressure would actually need to be handled at the sender (csrng_ctr_drbg_gen).
  // In this particular case, it is safe to unconditionally push the genbits FIFO because
  // the GenSOP FSM state which triggers csrng_ctr_drbg_gen to generate bits can only be reached
  // after checking that the genbits FIFO isn't full already. This condition is checked using an
  // SVA below.
  //
  // If the genbits FIFO got pushed without having space, this either means the output of a genbits
  // request is routed to the wrong application interface (which would be a critical design bug)
  // or that some fault injection attack is going on. Thus, we track such cases both with an SVA
  // and with a fatal alert (identifiable via the ERR_CODE register).
  assign sfifo_genbits_push = cs_enable_i && genbits_vld_i;

  assign sfifo_genbits_pop = genbits_vld_o && genbits_rdy_i;

  assign genbits_vld_o = cs_enable_i && sfifo_genbits_not_empty;
  assign {genbits_fips_o, genbits_bus_o} = sfifo_genbits_rdata;

  assign sfifo_genbits_err =
         {(sfifo_genbits_push && sfifo_genbits_full),
          (sfifo_genbits_pop && !sfifo_genbits_not_empty),
          (sfifo_genbits_full && !sfifo_genbits_not_empty)};

  // We're only allowed to request more bits if the genbits FIFO has indeed space.
  `ASSERT(CsrngCmdStageGenbitsFifoFull_A, state_q == GenSOP |-> !sfifo_genbits_full)

  // Pushes to the genbits FIFO outside of the GenCmdChk and CmdAck states or while handling a
  // command other than Generate are not allowed.
  `ASSERT(CsrngCmdStageGenbitsFifoPushExpected_A,
      sfifo_genbits_push |-> state_q inside {GenCmdChk, CmdAck} && cmd_gen_flag_q)

  //---------------------------------------------------------
  // Ack logic.
  //---------------------------------------------------------

  assign cmd_ack_d =
         (!cs_enable_i) ? '0 :
         cmd_final_ack || cmd_err_ack;

  assign cmd_stage_ack_o = cmd_ack_q;

  assign err_sts = reseed_cnt_exceeded ? CMD_STS_RESEED_CNT_EXCEEDED :
                   invalid_cmd_seq     ? CMD_STS_INVALID_CMD_SEQ     :
                   invalid_acmd        ? CMD_STS_INVALID_ACMD        : CMD_STS_INVALID_ACMD;

  assign cmd_ack_sts_d =
         (!cs_enable_i) ? CMD_STS_SUCCESS :
         cmd_err_ack ? err_sts :
         cmd_final_ack ? cmd_ack_sts_i :
         cmd_ack_sts_q;

  assign cmd_stage_ack_sts_o = cmd_ack_sts_q;

  assign reseed_cnt_alert_o = reseed_cnt_exceeded;
  assign invalid_cmd_seq_alert_o = invalid_cmd_seq;
  assign invalid_acmd_alert_o = invalid_acmd;

  // Make sure that the state machine has a stable error state. This means that after the error
  // state is entered it will not exit it unless a reset signal is received.
  `ASSERT(CsrngCmdStageErrorStStable_A, state_q == Error |=> $stable(state_q))
  // If in error state, the error output must be high.
  `ASSERT(CsrngCmdStageErrorOutput_A,   state_q == Error |-> cmd_stage_sm_err_o)
endmodule
