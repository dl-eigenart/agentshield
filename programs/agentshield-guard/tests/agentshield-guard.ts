import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { AgentshieldGuard } from "../target/types/agentshield_guard";
import { expect } from "chai";
import { PublicKey, Keypair, LAMPORTS_PER_SOL } from "@solana/web3.js";

describe("agentshield-guard", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.agentshieldGuard as Program<AgentshieldGuard>;
  const operator = provider.wallet;
  const agentId = "test-agent-001";

  // Derive the guard config PDA
  const [guardConfigPda] = PublicKey.findProgramAddressSync(
    [Buffer.from("guard"), operator.publicKey.toBuffer(), Buffer.from(agentId)],
    program.programId
  );

  const agent = Keypair.generate();
  const recipient = Keypair.generate();

  before(async () => {
    // Fund agent wallet
    const sig = await provider.connection.requestAirdrop(
      agent.publicKey,
      5 * LAMPORTS_PER_SOL
    );
    await provider.connection.confirmTransaction(sig);
  });

  it("Initializes guard config", async () => {
    const tx = await program.methods
      .initializeGuard(
        agentId,
        new anchor.BN(1_000_000_000), // 1 SOL max per tx
        new anchor.BN(5_000_000_000), // 5 SOL daily limit
        5,                             // circuit breaker: 5 denials
        new anchor.BN(300),            // in 300 seconds window
      )
      .accounts({
        guardConfig: guardConfigPda,
        operator: operator.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .rpc();

    const config = await program.account.guardConfig.fetch(guardConfigPda);
    expect(config.agentId).to.equal(agentId);
    expect(config.maxTxLamports.toNumber()).to.equal(1_000_000_000);
    expect(config.dailyLimitLamports.toNumber()).to.equal(5_000_000_000);
    expect(config.isLocked).to.be.false;
    expect(config.totalRequests.toNumber()).to.equal(0);
    console.log("  Guard initialized, PDA:", guardConfigPda.toBase58());
  });

  it("Adds recipient to allowlist", async () => {
    await program.methods
      .addToAllowlist(recipient.publicKey)
      .accounts({
        guardConfig: guardConfigPda,
        operator: operator.publicKey,
      })
      .rpc();

    const config = await program.account.guardConfig.fetch(guardConfigPda);
    expect(config.allowlist.length).to.equal(1);
    expect(config.allowlist[0].toBase58()).to.equal(recipient.publicKey.toBase58());
  });

  it("Auto-approves transfer within limits to allowlisted address", async () => {
    const config = await program.account.guardConfig.fetch(guardConfigPda);
    const requestNum = config.totalRequests.toNumber();

    const [txRequestPda] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("tx_req"),
        guardConfigPda.toBuffer(),
        new anchor.BN(requestNum).toArrayLike(Buffer, "le", 8),
      ],
      program.programId
    );

    await program.methods
      .submitRequest(
        recipient.publicKey,
        new anchor.BN(500_000_000), // 0.5 SOL
        "Test transfer",
      )
      .accounts({
        guardConfig: guardConfigPda,
        txRequest: txRequestPda,
        agent: agent.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .signers([agent])
      .rpc();

    const request = await program.account.transactionRequest.fetch(txRequestPda);
    expect(JSON.stringify(request.status)).to.include("approved");
    expect(request.lamports.toNumber()).to.equal(500_000_000);
    console.log("  Request auto-approved (0.5 SOL to allowlisted)");
  });

  it("Executes approved transfer", async () => {
    const [txRequestPda] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("tx_req"),
        guardConfigPda.toBuffer(),
        new anchor.BN(0).toArrayLike(Buffer, "le", 8),
      ],
      program.programId
    );

    const recipientBalBefore = await provider.connection.getBalance(recipient.publicKey);

    await program.methods
      .executeTransfer()
      .accounts({
        guardConfig: guardConfigPda,
        txRequest: txRequestPda,
        agent: agent.publicKey,
        recipient: recipient.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .signers([agent])
      .rpc();

    const recipientBalAfter = await provider.connection.getBalance(recipient.publicKey);
    expect(recipientBalAfter - recipientBalBefore).to.equal(500_000_000);
    console.log("  Transfer executed: 0.5 SOL received by recipient");
  });

  it("Denies transfer exceeding per-tx limit", async () => {
    const config = await program.account.guardConfig.fetch(guardConfigPda);
    const requestNum = config.totalRequests.toNumber();

    const [txRequestPda] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("tx_req"),
        guardConfigPda.toBuffer(),
        new anchor.BN(requestNum).toArrayLike(Buffer, "le", 8),
      ],
      program.programId
    );

    await program.methods
      .submitRequest(
        recipient.publicKey,
        new anchor.BN(2_000_000_000), // 2 SOL > 1 SOL limit
        "Over limit transfer",
      )
      .accounts({
        guardConfig: guardConfigPda,
        txRequest: txRequestPda,
        agent: agent.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .signers([agent])
      .rpc();

    const request = await program.account.transactionRequest.fetch(txRequestPda);
    expect(JSON.stringify(request.status)).to.include("denied");
    expect(request.denyReason).to.include("per-transaction limit");
    console.log("  Request denied: exceeds 1 SOL per-tx limit");
  });

  it("Sets oracle for approval workflow", async () => {
    const oracle = Keypair.generate();

    await program.methods
      .setOracle(oracle.publicKey)
      .accounts({
        guardConfig: guardConfigPda,
        operator: operator.publicKey,
      })
      .rpc();

    const config = await program.account.guardConfig.fetch(guardConfigPda);
    expect(config.oracle.toBase58()).to.equal(oracle.publicKey.toBase58());
    console.log("  Oracle set:", oracle.publicKey.toBase58());
  });

  it("Force-locks the guard", async () => {
    await program.methods
      .forceLock()
      .accounts({
        guardConfig: guardConfigPda,
        operator: operator.publicKey,
      })
      .rpc();

    const config = await program.account.guardConfig.fetch(guardConfigPda);
    expect(config.isLocked).to.be.true;
    console.log("  Guard force-locked");
  });

  it("Rejects submit when locked", async () => {
    const config = await program.account.guardConfig.fetch(guardConfigPda);
    const requestNum = config.totalRequests.toNumber();

    const [txRequestPda] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("tx_req"),
        guardConfigPda.toBuffer(),
        new anchor.BN(requestNum).toArrayLike(Buffer, "le", 8),
      ],
      program.programId
    );

    try {
      await program.methods
        .submitRequest(
          recipient.publicKey,
          new anchor.BN(100_000_000),
          "Should fail",
        )
        .accounts({
          guardConfig: guardConfigPda,
          txRequest: txRequestPda,
          agent: agent.publicKey,
          systemProgram: anchor.web3.SystemProgram.programId,
        })
        .signers([agent])
        .rpc();
      expect.fail("Should have thrown");
    } catch (err: any) {
      expect(err.toString()).to.include("CircuitBreakerLocked");
      console.log("  Submit rejected: circuit breaker locked");
    }
  });

  it("Unlocks the guard", async () => {
    await program.methods
      .unlock()
      .accounts({
        guardConfig: guardConfigPda,
        operator: operator.publicKey,
      })
      .rpc();

    const config = await program.account.guardConfig.fetch(guardConfigPda);
    expect(config.isLocked).to.be.false;
    console.log("  Guard unlocked");
  });

  it("Updates limits", async () => {
    await program.methods
      .updateLimits(
        new anchor.BN(2_000_000_000), // new max: 2 SOL
        new anchor.BN(10_000_000_000), // new daily: 10 SOL
      )
      .accounts({
        guardConfig: guardConfigPda,
        operator: operator.publicKey,
      })
      .rpc();

    const config = await program.account.guardConfig.fetch(guardConfigPda);
    expect(config.maxTxLamports.toNumber()).to.equal(2_000_000_000);
    expect(config.dailyLimitLamports.toNumber()).to.equal(10_000_000_000);
    console.log("  Limits updated: max=2 SOL, daily=10 SOL");
  });
});
