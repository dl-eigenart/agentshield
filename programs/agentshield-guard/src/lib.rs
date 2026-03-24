use anchor_lang::prelude::*;
use anchor_lang::system_program;

declare_id!("gURRDzQGXs7p4DrTt6dXPNFXHdwuK5u7WUHYobHMB1D");

// ─── Constants ─────────────────────────────────────────────────

const MAX_ALLOWLIST: usize = 20;
const MAX_DENY_REASONS: usize = 128;

// ─── Program ───────────────────────────────────────────────────

#[program]
pub mod agentshield_guard {
    use super::*;

    /// Initialize guard configuration for an agent.
    /// Only the operator (deployer) can call this.
    pub fn initialize_guard(
        ctx: Context<InitializeGuard>,
        agent_id: String,
        max_tx_lamports: u64,
        daily_limit_lamports: u64,
        circuit_breaker_threshold: u8,
        circuit_breaker_window_secs: i64,
    ) -> Result<()> {
        require!(agent_id.len() <= 32, AgentShieldError::AgentIdTooLong);
        require!(max_tx_lamports > 0, AgentShieldError::InvalidLimit);
        require!(daily_limit_lamports > 0, AgentShieldError::InvalidLimit);
        require!(circuit_breaker_threshold > 0, AgentShieldError::InvalidLimit);

        let config = &mut ctx.accounts.guard_config;
        config.operator = ctx.accounts.operator.key();
        config.agent_id = agent_id;
        config.max_tx_lamports = max_tx_lamports;
        config.daily_limit_lamports = daily_limit_lamports;
        config.daily_spent_lamports = 0;
        config.daily_reset_timestamp = Clock::get()?.unix_timestamp;
        config.circuit_breaker_threshold = circuit_breaker_threshold;
        config.circuit_breaker_window_secs = circuit_breaker_window_secs;
        config.blocked_count = 0;
        config.first_block_timestamp = 0;
        config.is_locked = false;
        config.total_requests = 0;
        config.total_approved = 0;
        config.total_denied = 0;
        config.allowlist = Vec::new();
        config.oracle = None;
        config.bump = ctx.bumps.guard_config;

        msg!("AgentShield Guard initialized for agent: {}", config.agent_id);
        Ok(())
    }

    /// Set the off-chain policy oracle that can approve/deny requests.
    pub fn set_oracle(ctx: Context<OperatorOnly>, oracle: Pubkey) -> Result<()> {
        let config = &mut ctx.accounts.guard_config;
        config.oracle = Some(oracle);
        msg!("Oracle set to: {}", oracle);
        Ok(())
    }

    /// Add a wallet address to the allowlist.
    pub fn add_to_allowlist(ctx: Context<OperatorOnly>, wallet: Pubkey) -> Result<()> {
        let config = &mut ctx.accounts.guard_config;
        require!(
            config.allowlist.len() < MAX_ALLOWLIST,
            AgentShieldError::AllowlistFull
        );
        if !config.allowlist.contains(&wallet) {
            config.allowlist.push(wallet);
            msg!("Added {} to allowlist", wallet);
        }
        Ok(())
    }

    /// Remove a wallet address from the allowlist.
    pub fn remove_from_allowlist(ctx: Context<OperatorOnly>, wallet: Pubkey) -> Result<()> {
        let config = &mut ctx.accounts.guard_config;
        config.allowlist.retain(|w| w != &wallet);
        msg!("Removed {} from allowlist", wallet);
        Ok(())
    }

    /// Submit a transaction request from the agent.
    /// The agent signs this; the request enters a pending state
    /// until approved by the oracle or auto-approved if within policy.
    pub fn submit_request(
        ctx: Context<SubmitRequest>,
        recipient: Pubkey,
        lamports: u64,
        memo: String,
    ) -> Result<()> {
        let clock = Clock::get()?;

        // Grab the guard_config key BEFORE mutable borrow
        let guard_config_key = ctx.accounts.guard_config.key();
        let agent_key = ctx.accounts.agent.key();
        let config = &mut ctx.accounts.guard_config;

        require!(!config.is_locked, AgentShieldError::CircuitBreakerLocked);
        require!(memo.len() <= 128, AgentShieldError::MemoTooLong);

        // Reset daily counter if new day (86400 seconds)
        if clock.unix_timestamp - config.daily_reset_timestamp >= 86400 {
            config.daily_spent_lamports = 0;
            config.daily_reset_timestamp = clock.unix_timestamp;
        }

        // Policy checks
        let within_tx_limit = lamports <= config.max_tx_lamports;
        let within_daily_limit = config.daily_spent_lamports + lamports <= config.daily_limit_lamports;
        let in_allowlist = config.allowlist.contains(&recipient);
        let has_oracle = config.oracle.is_some();

        // Auto-approve if: within limits AND (in allowlist OR no oracle configured)
        let auto_approve = within_tx_limit && within_daily_limit && (in_allowlist || !has_oracle);

        // Determine status and deny reason
        let (status, deny_reason) = if auto_approve {
            (RequestStatus::Approved, String::new())
        } else if !within_tx_limit {
            config.total_denied += 1;
            trigger_circuit_breaker(config, clock.unix_timestamp);
            (RequestStatus::Denied, String::from("Exceeds per-transaction limit"))
        } else if !within_daily_limit {
            config.total_denied += 1;
            trigger_circuit_breaker(config, clock.unix_timestamp);
            (RequestStatus::Denied, String::from("Exceeds daily spending limit"))
        } else {
            // Needs oracle approval
            (RequestStatus::Pending, String::new())
        };

        let request_num = config.total_requests;
        config.total_requests += 1;
        if auto_approve {
            config.total_approved += 1;
        }

        // Now populate the request account
        let request = &mut ctx.accounts.tx_request;
        request.guard_config = guard_config_key;
        request.agent = agent_key;
        request.recipient = recipient;
        request.lamports = lamports;
        request.memo = memo;
        request.status = status;
        request.submitted_at = clock.unix_timestamp;
        request.resolved_at = if auto_approve { clock.unix_timestamp } else { 0 };
        request.deny_reason = deny_reason;
        request.bump = ctx.bumps.tx_request;

        msg!(
            "TX Request #{}: {} lamports to {} → {:?}",
            request_num,
            lamports,
            recipient,
            request.status
        );

        Ok(())
    }

    /// Oracle approves a pending request.
    pub fn oracle_approve(ctx: Context<OracleAction>) -> Result<()> {
        let request = &mut ctx.accounts.tx_request;
        let clock = Clock::get()?;

        require!(
            request.status == RequestStatus::Pending,
            AgentShieldError::RequestNotPending
        );

        // Verify signer is the oracle
        let config = &ctx.accounts.guard_config;
        require!(
            config.oracle == Some(ctx.accounts.oracle.key()),
            AgentShieldError::NotOracle
        );

        request.status = RequestStatus::Approved;
        request.resolved_at = clock.unix_timestamp;

        let config_mut = &mut ctx.accounts.guard_config;
        config_mut.total_approved += 1;

        msg!("Oracle approved request");
        Ok(())
    }

    /// Oracle denies a pending request.
    pub fn oracle_deny(ctx: Context<OracleAction>, reason: String) -> Result<()> {
        let request = &mut ctx.accounts.tx_request;
        let clock = Clock::get()?;

        require!(
            request.status == RequestStatus::Pending,
            AgentShieldError::RequestNotPending
        );

        let config = &ctx.accounts.guard_config;
        require!(
            config.oracle == Some(ctx.accounts.oracle.key()),
            AgentShieldError::NotOracle
        );
        require!(reason.len() <= MAX_DENY_REASONS, AgentShieldError::MemoTooLong);

        request.status = RequestStatus::Denied;
        request.resolved_at = clock.unix_timestamp;
        request.deny_reason = reason;

        let config_mut = &mut ctx.accounts.guard_config;
        config_mut.total_denied += 1;
        trigger_circuit_breaker(config_mut, clock.unix_timestamp);

        msg!("Oracle denied request");
        Ok(())
    }

    /// Execute an approved transfer. Transfers SOL from agent to recipient.
    pub fn execute_transfer(ctx: Context<ExecuteTransfer>) -> Result<()> {
        let request = &mut ctx.accounts.tx_request;
        let config = &mut ctx.accounts.guard_config;

        require!(!config.is_locked, AgentShieldError::CircuitBreakerLocked);
        require!(
            request.status == RequestStatus::Approved,
            AgentShieldError::RequestNotApproved
        );

        // Transfer SOL from agent to recipient
        system_program::transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                system_program::Transfer {
                    from: ctx.accounts.agent.to_account_info(),
                    to: ctx.accounts.recipient.to_account_info(),
                },
            ),
            request.lamports,
        )?;

        // Update daily spending
        config.daily_spent_lamports += request.lamports;

        // Mark as executed
        request.status = RequestStatus::Executed;
        request.resolved_at = Clock::get()?.unix_timestamp;

        msg!(
            "Executed: {} lamports to {}",
            request.lamports,
            request.recipient
        );

        Ok(())
    }

    /// Operator can force-lock the guard (emergency).
    pub fn force_lock(ctx: Context<OperatorOnly>) -> Result<()> {
        let config = &mut ctx.accounts.guard_config;
        config.is_locked = true;
        msg!("Guard FORCE LOCKED by operator");
        Ok(())
    }

    /// Operator can unlock the guard.
    pub fn unlock(ctx: Context<OperatorOnly>) -> Result<()> {
        let config = &mut ctx.accounts.guard_config;
        config.is_locked = false;
        config.blocked_count = 0;
        config.first_block_timestamp = 0;
        msg!("Guard UNLOCKED by operator");
        Ok(())
    }

    /// Update guard configuration limits.
    pub fn update_limits(
        ctx: Context<OperatorOnly>,
        max_tx_lamports: u64,
        daily_limit_lamports: u64,
    ) -> Result<()> {
        require!(max_tx_lamports > 0, AgentShieldError::InvalidLimit);
        require!(daily_limit_lamports > 0, AgentShieldError::InvalidLimit);
        let config = &mut ctx.accounts.guard_config;
        config.max_tx_lamports = max_tx_lamports;
        config.daily_limit_lamports = daily_limit_lamports;
        msg!("Limits updated: max_tx={}, daily={}", max_tx_lamports, daily_limit_lamports);
        Ok(())
    }
}

// ─── Circuit Breaker Logic ─────────────────────────────────────

fn trigger_circuit_breaker(config: &mut GuardConfig, now: i64) {
    if config.first_block_timestamp == 0
        || now - config.first_block_timestamp > config.circuit_breaker_window_secs
    {
        config.first_block_timestamp = now;
        config.blocked_count = 1;
    } else {
        config.blocked_count += 1;
    }

    if config.blocked_count >= config.circuit_breaker_threshold {
        config.is_locked = true;
        msg!(
            "CIRCUIT BREAKER TRIGGERED: {} denials in {} seconds → LOCKED",
            config.blocked_count,
            now - config.first_block_timestamp
        );
    }
}

// ─── Account Structures ────────────────────────────────────────

#[account]
pub struct GuardConfig {
    pub operator: Pubkey,
    pub agent_id: String,             // max 32 chars
    pub max_tx_lamports: u64,
    pub daily_limit_lamports: u64,
    pub daily_spent_lamports: u64,
    pub daily_reset_timestamp: i64,
    pub circuit_breaker_threshold: u8,
    pub circuit_breaker_window_secs: i64,
    pub blocked_count: u8,
    pub first_block_timestamp: i64,
    pub is_locked: bool,
    pub total_requests: u64,
    pub total_approved: u64,
    pub total_denied: u64,
    pub allowlist: Vec<Pubkey>,       // max 20 entries
    pub oracle: Option<Pubkey>,
    pub bump: u8,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, PartialEq, Eq, Debug)]
pub enum RequestStatus {
    Pending,
    Approved,
    Denied,
    Executed,
    Expired,
}

#[account]
pub struct TransactionRequest {
    pub guard_config: Pubkey,
    pub agent: Pubkey,
    pub recipient: Pubkey,
    pub lamports: u64,
    pub memo: String,                 // max 128 chars
    pub status: RequestStatus,
    pub submitted_at: i64,
    pub resolved_at: i64,
    pub deny_reason: String,          // max 128 chars
    pub bump: u8,
}

// ─── Account Contexts ──────────────────────────────────────────

#[derive(Accounts)]
#[instruction(agent_id: String)]
pub struct InitializeGuard<'info> {
    #[account(
        init,
        payer = operator,
        space = 8 + 32 + (4 + 32) + 8 + 8 + 8 + 8 + 1 + 8 + 1 + 8 + 1 + 8 + 8 + 8 + (4 + 32 * MAX_ALLOWLIST) + (1 + 32) + 1 + 64,
        seeds = [b"guard", operator.key().as_ref(), agent_id.as_bytes()],
        bump,
    )]
    pub guard_config: Account<'info, GuardConfig>,
    #[account(mut)]
    pub operator: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct OperatorOnly<'info> {
    #[account(
        mut,
        has_one = operator,
    )]
    pub guard_config: Account<'info, GuardConfig>,
    pub operator: Signer<'info>,
}

#[derive(Accounts)]
pub struct SubmitRequest<'info> {
    #[account(mut)]
    pub guard_config: Account<'info, GuardConfig>,
    #[account(
        init,
        payer = agent,
        space = 8 + 32 + 32 + 32 + 8 + (4 + 128) + 1 + 8 + 8 + (4 + 128) + 1 + 64,
        seeds = [
            b"tx_req",
            guard_config.key().as_ref(),
            &guard_config.total_requests.to_le_bytes(),
        ],
        bump,
    )]
    pub tx_request: Account<'info, TransactionRequest>,
    #[account(mut)]
    pub agent: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct OracleAction<'info> {
    #[account(mut)]
    pub guard_config: Account<'info, GuardConfig>,
    #[account(
        mut,
        has_one = guard_config,
    )]
    pub tx_request: Account<'info, TransactionRequest>,
    pub oracle: Signer<'info>,
}

#[derive(Accounts)]
pub struct ExecuteTransfer<'info> {
    #[account(mut)]
    pub guard_config: Account<'info, GuardConfig>,
    #[account(
        mut,
        has_one = guard_config,
        has_one = recipient,
    )]
    pub tx_request: Account<'info, TransactionRequest>,
    #[account(mut)]
    pub agent: Signer<'info>,
    /// CHECK: Validated by tx_request.recipient constraint
    #[account(mut)]
    pub recipient: AccountInfo<'info>,
    pub system_program: Program<'info, System>,
}

// ─── Errors ────────────────────────────────────────────────────

#[error_code]
pub enum AgentShieldError {
    #[msg("Agent ID must be 32 characters or less")]
    AgentIdTooLong,
    #[msg("Limit values must be greater than zero")]
    InvalidLimit,
    #[msg("Allowlist is full (max 20 entries)")]
    AllowlistFull,
    #[msg("Memo must be 128 characters or less")]
    MemoTooLong,
    #[msg("Circuit breaker is locked — all transactions frozen")]
    CircuitBreakerLocked,
    #[msg("Transaction request is not in Pending status")]
    RequestNotPending,
    #[msg("Transaction request is not Approved")]
    RequestNotApproved,
    #[msg("Signer is not the authorized oracle")]
    NotOracle,
}
