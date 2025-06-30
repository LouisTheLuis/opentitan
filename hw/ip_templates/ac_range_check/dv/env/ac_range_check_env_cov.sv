// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

/**
 * Covergroups that are dependent on run-time parameters that may be available
 * only in build_phase can be defined here
 * Covergroups may also be wrapped inside helper classes if needed.
 */

class ac_range_check_env_cov extends cip_base_env_cov #(.CFG_T(ac_range_check_env_cfg));

  `uvm_component_utils(ac_range_check_env_cov)

  // The base class provides the following handles for use:
  // ac_range_check_env_cfg: cfg

  // Holds the type of TLUL transaction being processed by the predictor
  ac_range_check_env_pkg::access_type_e access_type_cp;

  int  idx_cp;     // Range Index for which coverage is sampled
  bit  read_cp;    // Read permission from CSR Attr field    1 = enabled, 0 = disabled
  bit  write_cp;   // Write permission from CSR Attr field   1 = enabled, 0 = disabled
  bit  execute_cp; // Execute permission from CSR Attr field 1 = enabled, 0 = disabled
  int  role_cp;    // Holds RACL Role Identifier

  bit  access_permit_cp; // Access due to permissions 1 = Access permitted, 0 = Access denied
  bit  racl_cp;          // Access due to RACL Check  1 = Access permitted, 0 = Access denied
  bit  range_en_cp;      // State of specific Range Index at sampling point
                         // 1 = enabled, 0 = disabled

  bit  addr_hit_cp;       // State of Address Check at sampling 1 = hit, 0 = miss
  bit  all_index_miss_cp; // 1 = addr miss on all indexes, 0 = addr hit on some index range

  bit  bypass_cp;   // Bypass Mode 1 = enabled, 0 = disabled
  bit  lock_idx_cp; // Status of lock bit for an index 1 = locked,  0 = unlocked

  bit  intr_cp;         // Interrupt signal 1 = raised, 0 = dropped
  bit  intr_state_cp;   // Interrupt state 1 = raised, 0 = dropped
  bit  intr_enable_cp;  // Interrupt enable 1 = enabled, 0 = disabled
  bit  intr_test_cp;    // Interrupt test 1 = enabled, 0 = disabled

  int  ctn_uid_cp;    // Holds source CTN UID
  bit  racl_write_cp; // RACL write, 1 = Access permitted, 0 = Access denied
  bit  racl_read_cp;  // RACL read, 1 = Access permitted, 0 = Access denied
  bit  log_enable_cp; // Log enable 1 = enabled, 0 = disabled
  bit  log_clear_cp;  // Log clear 1 = enabled, 0 = disabled
  bit  log_denied_cp; // Log denied access 1 = enabled, 0 = disabled

  // Primary covergroup that verifies the operation of AC_RANGE_CHECK module.
  // There are 4 parts to the cross in this covergroup.
  // - Index that had the address match
  // - Type of transaction observed
  // - RWX permissions that was configured
  // - Access Granted / Denied
  //
  // Illegal bins are specified to ensure all combinations that can never be seen are excluded from
  // coverage reports and make them clean. If ever a situation is observed where an illegal_bins is
  // sampled, it is treated on par with assertions and will trigger a simulation failure at the
  // point of sampling an illegal bin.

  covergroup attr_perm_cg;
    coverpoint idx_cp
    {
      bins index[] = {[0:NUM_RANGES-1]};
    }

    coverpoint access_type_cp;
    coverpoint read_cp    { bins disabled = {0}; bins enabled = {1}; }
    coverpoint write_cp   { bins disabled = {0}; bins enabled = {1}; }
    coverpoint execute_cp { bins disabled = {0}; bins enabled = {1}; }


    coverpoint access_permit_cp { bins deny = {0}; bins permit = {1}; }

    idx_X_access_type_X_read_X_write_X_execute_X_access_permit:
         cross idx_cp, access_type_cp, read_cp, write_cp, execute_cp, access_permit_cp
    {

      // If an execute transaction is observed and execute permission is enabled
      // the transaction can never be filtered out.
      illegal_bins deny_when_ex_is_set =
                              binsof (access_type_cp) intersect {ac_range_check_env_pkg::Execute}
                           && binsof (execute_cp) intersect {1}
                           && binsof (access_permit_cp) intersect {0};

      // If an execute transaction is observed and execute permission is disabled
      // the transaction will always be filtered out.
      illegal_bins  permit_when_ex_unset =
                              binsof (access_type_cp) intersect {ac_range_check_env_pkg::Execute}
                           && binsof (execute_cp) intersect {0}
                           && binsof (access_permit_cp) intersect {1};


      // If a write transaction is observed and write permissions are enabled
      // the transaction can never be filtered out.
      illegal_bins deny_when_wr_is_set =
                                binsof (access_type_cp) intersect {ac_range_check_env_pkg::Write}
                             && binsof (write_cp) intersect {1}
                             && binsof (access_permit_cp) intersect {0};

      // If a write transaction is observed and write permission is disabled
      // the transaction will always be filtered out.
      illegal_bins permit_when_wr_unset =
                                binsof (access_type_cp) intersect {ac_range_check_env_pkg::Write}
                             && binsof (write_cp) intersect {0}
                             && binsof (access_permit_cp) intersect {1};


      // If a read transaction is observed and read permissions are enabled
      // the transaction can never be filtered out.
      illegal_bins deny_when_rd_is_set =
                                 binsof (access_type_cp) intersect {ac_range_check_env_pkg::Read}
                              && binsof (read_cp) intersect {1}
                              && binsof (access_permit_cp) intersect {0};

      // If a read transaction is observed and read permission is disabled
      // the transaction will always be filtered out.
      illegal_bins permit_when_rd_unset =
                                 binsof (access_type_cp) intersect {ac_range_check_env_pkg::Read}
                              && binsof (read_cp) intersect {0}
                              && binsof (access_permit_cp) intersect {1};
    }
  endgroup : attr_perm_cg


  // RACL checks are not performed when normal range check has failed.
  // This covergroup is sampled when RACL checks are performed.
  covergroup racl_cg;
    coverpoint idx_cp
    {
      bins index[] = {[0:NUM_RANGES-1]};
    }

    coverpoint role_cp
    {
      bins role[]  = {[0:NUM_ROLES-1]};
    }

    coverpoint access_type_cp;
    coverpoint racl_cp { bins deny = {0}; bins permit = {1}; }

    idx_X_access_type_X_role_X_racl : cross idx_cp, access_type_cp, role_cp, racl_cp;
  endgroup : racl_cg

  // To observe that each index is enabled or disabled.
  covergroup range_cg;
    coverpoint idx_cp
    {
      bins index[] = {[0:NUM_RANGES-1]};
    }

    coverpoint range_en_cp { bins disabled = {0}; bins enabled = {1}; }

    idx_X_range_en : cross idx_cp, range_en_cp;
  endgroup : range_cg

  // To ensure address matches are observed on all range indexes.
  covergroup addr_match_cg;
    coverpoint idx_cp
    {
      bins index[] = {[0:NUM_RANGES-1]};
    }

    coverpoint addr_hit_cp { bins miss = {0}; bins hit = {1}; }

    idx_X_addr_hit : cross idx_cp, addr_hit_cp;
  endgroup : addr_match_cg

  // all_index_miss_cg is a negative covergroup.
  // A situtation can occur when a TLUL transaction being checked by ac_range will miss all
  // configured indexes and be denied.
  covergroup all_index_miss_cg;
    coverpoint all_index_miss_cp { bins addr_hit_seen = {0};
                                   bins addr_not_matched_in_any_index = {1}; }
  endgroup : all_index_miss_cg

  covergroup bypass_cg;
    coverpoint bypass_cp { bins disabled = {0}; bins enabled = {1}; }
  endgroup : bypass_cg

  covergroup range_lock_cg;
    coverpoint idx_cp
    {
      bins index[] = {[0:NUM_RANGES-1]};
    }

    coverpoint range_en_cp   { bins disabled = {0}; bins enabled = {1}; }
    coverpoint lock_idx_cp { bins unlocked = {0}; bins locked = {1}; }

    idx_X_enable_X_lock : cross idx_cp, range_en_cp, lock_idx_cp;
  endgroup : range_lock_cg

  covergroup intr_cg;
    coverpoint intr_cp { bins dropped = {0}; bins raised = {1}; }
    coverpoint intr_state_cp { bins dropped = {0}; bins raised = {1}; }
    coverpoint intr_enable_cp { bins disabled = {0}; bins enabled = {1}; }
    coverpoint intr_test_cp { bins disabled = {0}; bins enabled = {1}; }

    intr_X_state_X_enable_X_test : cross intr_cp, intr_state_cp, intr_enable_cp, intr_test_cp;
  endgroup : intr_cg

  covergroup log_intr_cg; 
    coverpoint idx_cp 
    {
      bins index[] = {[0:NUM_RANGES-1]};
    }

    coverpoint ctn_uid_cp
    {
      bins uid[]   = {[0:31]};
    }

    coverpoint role_cp 
    {
      bins role[]  = {[0:NUM_ROLES-1]}; 
    }

    coverpoint racl_write_cp { bins deny = {0}; bins permit = {1}; }
    coverpoint racl_read_cp { bins deny = {0}; bins permit = {1}; }
    coverpoint all_index_miss_cp { bins addr_hit_seen = {0};
                                   bins addr_not_matched_in_any_index = {1}; }
    coverpoint read_cp    { bins disabled = {0}; bins enabled = {1}; }
    coverpoint write_cp   { bins disabled = {0}; bins enabled = {1}; }
    coverpoint execute_cp { bins disabled = {0}; bins enabled = {1}; }
    coverpoint log_enable_cp { bins disabled = {0}; bins enabled = {1}; }
    coverpoint log_clear_cp { bins disabled = {0}; bins enabled = {1}; }
    coverpoint log_denied_cp { bins disabled = {0}; bins enabled = {1}; }
    
    idx_X_ctn_uid_X_role_X_racl_write_X_racl_read_X_no_match_X_read_X_write_X_execute:
         cross idx_cp, ctn_uid_cp, racl_write_cp, racl_read_cp, all_index_miss_cp,
               read_cp, write_cp, execute_cp, log_enable_cp, log_clear_cp, log_denied_cp
    {
      // If log_clear is raised, then all the fields should be cleared.
      illegal_bins clear_when_log_clear_is_set =
                           binsof (log_clear_cp) intersect {1}
                    && ( !(binsof (ctn_uid_cp) intersect {0})
                    || !(binsof (role_cp) intersect {0})
                    || !(binsof (racl_write_cp) intersect {0})
                    || !(binsof (racl_read_cp) intersect {0})
                    || !(binsof (all_index_miss_cp) intersect {0})
                    || !(binsof (read_cp) intersect {0})
                    || !(binsof (write_cp) intersect {0})
                    || !(binsof (execute_cp) intersect {0}) );

      // If logging is globally disabled, then all the fields should be empty.
      illegal_bins empty_when_log_enable_is_not_set =
                           binsof (log_enable_cp) intersect {0}
                    && ( !(binsof (ctn_uid_cp) intersect {0})
                    || !(binsof (role_cp) intersect {0})
                    || !(binsof (racl_write_cp) intersect {0})
                    || !(binsof (racl_read_cp) intersect {0})
                    || !(binsof (all_index_miss_cp) intersect {0})
                    || !(binsof (read_cp) intersect {0})
                    || !(binsof (write_cp) intersect {0})
                    || !(binsof (execute_cp) intersect {0}) );

      // If the corresponding range has logging disabled, then all the fields
      // should be empty.
      illegal_bins empty_when_log_disabled = 
                           binsof (log_denied_cp) intersect {0}
                    && ( !(binsof (ctn_uid_cp) intersect {0})
                    || !(binsof (role_cp) intersect {0})
                    || !(binsof (racl_write_cp) intersect {0})
                    || !(binsof (racl_read_cp) intersect {0})
                    || !(binsof (all_index_miss_cp) intersect {0})
                    || !(binsof (read_cp) intersect {0})
                    || !(binsof (write_cp) intersect {0})
                    || !(binsof (execute_cp) intersect {0}) );
    }
  endgroup : log_intr_cg

  // Standard SV/UVM methods
  extern function new(string name, uvm_component parent);
  extern function void build_phase(uvm_phase phase);

  extern function void sample_attr_cg(int idx,
                                      ac_range_check_env_pkg::access_type_e access_type,
                                      bit read_perm, bit write_perm, bit execute_perm,
                                      bit acc_permit);
  extern function void sample_racl_cg(int idx,
                                      ac_range_check_env_pkg::access_type_e access_type,
                                      int role, bit racl_check);

  extern function void sample_range_cg(int idx, bit range_en);

  extern function void sample_all_index_miss_cg();
  extern function void sample_bypass_cg(bit bypass_en);
  extern function void sample_range_lock_cg(int idx, bit enable, bit lock);
  extern function void sample_intr_cg(bit intr, bit intr_state, bit intr_enable, bit intr_test);
  extern function void sample_log_intr_cg(int idx, int ctn_uid, int role, bit racl_write,
                                          bit racl_read, bit no_match, bit read, bit write, 
                                          bit execute, bit log_en, bit log_clr, bit log_dnd);
endclass : ac_range_check_env_cov


function ac_range_check_env_cov::new(string name, uvm_component parent);
  super.new(name, parent);
  attr_perm_cg      = new();
  racl_cg           = new();
  range_cg          = new();
  addr_match_cg     = new();
  all_index_miss_cg = new();
  bypass_cg         = new();
  range_lock_cg     = new();
  intr_cg           = new();
  log_intr_cg       = new();
endfunction : new

function void ac_range_check_env_cov::build_phase(uvm_phase phase);
  super.build_phase(phase);
  // Please instantiate sticky_intr_cov array of objects for all interrupts that are sticky
  // See cip_base_env_cov for details
endfunction : build_phase


function void ac_range_check_env_cov::sample_attr_cg(int idx,
                                             ac_range_check_env_pkg::access_type_e access_type,
                                             bit read_perm, bit write_perm, bit execute_perm,
                                             bit acc_permit);
  this.idx_cp           = idx;
  this.access_type_cp   = access_type;
  this.access_permit_cp = acc_permit;
  this.read_cp          = read_perm;
  this.write_cp         = write_perm;
  this.execute_cp       = execute_perm;

  attr_perm_cg.sample();
endfunction : sample_attr_cg

function void ac_range_check_env_cov::sample_racl_cg(int idx,
                                             ac_range_check_env_pkg::access_type_e access_type,
                                             int role, bit racl_check);
  this.idx_cp         = idx;
  this.access_type_cp = access_type;
  this.role_cp        = role;
  this.racl_cp        = racl_check;

  racl_cg.sample();
endfunction : sample_racl_cg

function void ac_range_check_env_cov::sample_range_cg(int idx, bit range_en);
  this.idx_cp      = idx;
  this.range_en_cp = range_en;

  range_cg.sample();
endfunction : sample_range_cg

function void ac_range_check_env_cov::sample_addr_match_cg(int idx, bit addr_hit);
  this.idx_cp      = idx;
  this.addr_hit_cp = addr_hit;

  addr_match_cg.sample();

  if (addr_hit) begin
    this.all_index_miss_cp = 0;
    all_index_miss_cg.sample();
  end
endfunction : sample_addr_match_cg

function void ac_range_check_env_cov::sample_all_index_miss_cg();
  this.all_index_miss_cp = 1;
  all_index_miss_cg.sample();
endfunction : sample_all_index_miss_cg

function void ac_range_check_env_cov::sample_bypass_cg(bit bypass_en);
  this.bypass_cp = bypass_en;
  bypass_cg.sample();
endfunction : sample_bypass_cg

function void ac_range_check_env_cov::sample_range_lock_cg(int idx, bit enable, bit lock);
  this.idx_cp      = idx;
  this.range_en_cp = enable;
  this.lock_idx_cp = lock;

  range_lock_cg.sample();
endfunction : sample_range_lock_cg

function void ac_range_check_env_cov::sample_intr_cg(bit intr, bit intr_state, bit intr_enable,
                                                     bit intr_test);
  this.intr_cp        = intr;
  this.intr_state_cp  = intr_state;
  this.intr_enable_cp = intr_enable;
  this.intr_test_cp   = intr_test;
  intr_cg.sample();
endfunction : sample_intr_cg

function void ac_range_check_env_cov::sample_log_intr_cg(bit idx, int ctn_uid, int role, 
                                                         bit racl_write, bit racl_read,
                                                         bit no_match, bit read, bit write,
                                                         bit execute, bit log_en, bit log_clr,
                                                         bit log_dnd);
  this.idx_cp            = idx;
  this.ctn_uid_cp        = ctn_uid;
  this.role_cp           = role;
  this.racl_write_cp     = racl_write;
  this.racl_read_cp      = racl_read;
  this.all_index_miss_cp = no_match;
  this.read_cp           = read;
  this.write_cp          = write;
  this.execute_cp        = execute;
  this.log_enable_cp     = log_en;
  this.log_clear_cp      = log_clr;
  this.log_denied_cp     = log_dnd; 
  log_intr_cg.sample();
endfunction : sample_log_intr_cg
