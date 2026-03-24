import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { AgentshieldGuard } from "../target/types/agentshield_guard";
import { expect } from "chai";
import { PublicKey, Keypair, LAMPORTS_PER_SOL, SystemProgram, Transaction } from "@solana/web3.js";

describe("agentshield-guard", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.agentshieldGuard as Program<AgentshieldGuard>;
  const operator = provider.wallet;
  const agentId = "test-agent-001";

  const [guardConfigPda] = PublicKey.findProgramAddressSync(
    [Buffer.from("guard"), operator.publicKey.toBuffer(), Buffer.from(agentId)],
    program.programId
  );

  const agent = Keypair.generate();
  const recipient = Keypair.generate();

  before(async () => {
    // Fund agent via transfer from operator (works on devnet without airdrop)
    const tx = new Transaction().add(
      SystemProgram.transfer({
        fromPubkey: operator.publicKey,
        toPubkey: agent.publicKey,
        lamports: 2 * LAMPORTS_PER_SOL,
      })
    );
    await provider.sendAndConfirm(tx);
    const bal = await provider.connection.getBalance(agent.publicKey);
    console.log("  Agent funded:", bal / LAMPORTS_PER_SOL, "SOL");
  });

  it("Initializes guard config", async () => {
    await program.methods
      .initializeGuard(agentId, new anchor.BN(1_000_000_000), new anchor.BN(5_000_000_000), 5, new anchor.BN(300))
      .accounts({ guardConfig: guardConfigPda, operator: operator.publicKey, systemProgram: SystemProgram.programId })
      .rpc();

    const config = await program.account.guardConfig.fetch(guardConfigPda);
    expect(config.agentId).to.equal(agentId);
    expect(config.maxTxLamports.toNumber()).to.equal(1_000_000_000);
    expect(config.isLocked).to.be.false;
    console.log("  Guard PDA:", guardConfigPda.toBase58());
  });

  it("Adds recipient to allowlist", async () => {
    await program.methods.addToAllowlist(recipient.publicKey)
      .accounts({ guardConfig: guardConfigPda, operator: operator.publicKey }).rpc();
    const config = await program.account.guardConfig.fetch(guardConfigPda);
    expect(config.allowlist.length).to.equal(1);
  });

  it("Auto-approves within limits to allowlisted", async () => {
    const config = await program.account.guardConfig.fetch(guardConfigPda);
    const [txReqPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("tx_req"), guardConfigPda.toBuffer(), new anchor.BN(config.totalRequests.toNumber()).toArrayLike(Buffer, "le", 8)],
      program.programId
    );
    await program.methods.submitRequest(recipient.publicKey, new anchor.BN(500_000_000), "Test transfer")
      .accounts({ guardConfig: guardConfigPda, txRequest: txReqPda, agent: agent.publicKey, systemProgram: SystemProgram.programId })
      .signers([agent]).rpc();
    const req = await program.account.transactionRequest.fetch(txReqPda);
    expect(JSON.stringify(req.status)).to.include("approved");
    console.log("  Auto-approved 0.5 SOL");
  });

  it("Executes approved transfer", async () => {
    const [txReqPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("tx_req"), guardConfigPda.toBuffer(), new anchor.BN(0).toArrayLike(Buffer, "le", 8)],
      program.programId
    );
    const before = await provider.connection.getBalance(recipient.publicKey);
    await program.methods.executeTransfer()
      .accounts({ guardConfig: guardConfigPda, txRequest: txReqPda, agent: agent.publicKey, recipient: recipient.publicKey, systemProgram: SystemProgram.programId })
      .signers([agent]).rpc();
    const after = await provider.connection.getBalance(recipient.publicKey);
    expect(after - before).to.equal(500_000_000);
    console.log("  Executed: 0.5 SOL transferred");
  });

  it("Denies transfer exceeding limit", async () => {
    const config = await program.account.guardConfig.fetch(guardConfigPda);
    const [txReqPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("tx_req"), guardConfigPda.toBuffer(), new anchor.BN(config.totalRequests.toNumber()).toArrayLike(Buffer, "le", 8)],
      program.programId
    );
    await program.methods.submitRequest(recipient.publicKey, new anchor.BN(2_000_000_000), "Over limit")
      .accounts({ guardConfig: guardConfigPda, txRequest: txReqPda, agent: agent.publicKey, systemProgram: SystemProgram.programId })
      .signers([agent]).rpc();
    const req = await program.account.transactionRequest.fetch(txReqPda);
    expect(JSON.stringify(req.status)).to.include("denied");
    console.log("  Denied: exceeds 1 SOL limit");
  });

  it("Sets oracle", async () => {
    const oracle = Keypair.generate();
    await program.methods.setOracle(oracle.publicKey)
      .accounts({ guardConfig: guardConfigPda, operator: operator.publicKey }).rpc();
    const config = await program.account.guardConfig.fetch(guardConfigPda);
    expect(config.oracle.toBase58()).to.equal(oracle.publicKey.toBase58());
  });

  it("Force-locks the guard", async () => {
    await program.methods.forceLock()
      .accounts({ guardConfig: guardConfigPda, operator: operator.publicKey }).rpc();
    const config = await program.account.guardConfig.fetch(guardConfigPda);
    expect(config.isLocked).to.be.true;
  });

  it("Rejects submit when locked", async () => {
    const config = await program.account.guardConfig.fetch(guardConfigPda);
    const [txReqPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("tx_req"), guardConfigPda.toBuffer(), new anchor.BN(config.totalRequests.toNumber()).toArrayLike(Buffer, "le", 8)],
      program.programId
    );
    try {
      await program.methods.submitRequest(recipient.publicKey, new anchor.BN(100_000_000), "Should fail")
        .accounts({ guardConfig: guardConfigPda, txRequest: txReqPda, agent: agent.publicKey, systemProgram: SystemProgram.programId })
        .signers([agent]).rpc();
      expect.fail("Should have thrown");
    } catch (err: any) {
      expect(err.toString()).to.include("CircuitBreakerLocked");
    }
  });

  it("Unlocks the guard", async () => {
    await program.methods.unlock()
      .accounts({ guardConfig: guardConfigPda, operator: operator.publicKey }).rpc();
    const config = await program.account.guardConfig.fetch(guardConfigPda);
    expect(config.isLocked).to.be.false;
  });

  it("Updates limits", async () => {
    await program.methods.updateLimits(new anchor.BN(2_000_000_000), new anchor.BN(10_000_000_000))
      .accounts({ guardConfig: guardConfigPda, operator: operator.publicKey }).rpc();
    const config = await program.account.guardConfig.fetch(guardConfigPda);
    expect(config.maxTxLamports.toNumber()).to.equal(2_000_000_000);
  });
});
