const { expect } = require("chai");
const { ethers }  = require("hardhat");

const VALID = 1; // IdentityStatus.VALID

describe("L3RS1Asset", function () {

  async function deploy() {
    const [owner, user1, user2] = await ethers.getSigners();
    const Factory = await ethers.getContractFactory("L3RS1Asset");
    const asset   = await Factory.deploy(
      ethers.randomBytes(33),
      100,
      ethers.randomBytes(32),
    );
    await asset.waitForDeployment();
    return { asset, owner, user1, user2 };
  }

  // Active asset with identity oracle = owner and a permissive compliance oracle wired.
  async function deployActive() {
    const ctx = await deploy();
    const { asset, owner } = ctx;
    await asset.activate();
    await asset.setIdentityOracle(owner.address);
    const Oracle = await ethers.getContractFactory("MockComplianceOracle");
    const oracle = await Oracle.deploy();
    await oracle.waitForDeployment();
    await asset.setComplianceOracle(await oracle.getAddress());
    return { ...ctx, oracle };
  }

  // ── §2.2 Asset_ID ────────────────────────────────────────────────────────────
  it("assetId() returns non-zero bytes32", async function () {
    const { asset } = await deploy();
    expect(await asset.assetId()).to.not.equal(ethers.ZeroHash);
  });

  it("two deployments produce different assetIds", async function () {
    const { asset: a1 } = await deploy();
    const { asset: a2 } = await deploy();
    expect(await a1.assetId()).to.not.equal(await a2.assetId());
  });

  // ── §2.4 State ────────────────────────────────────────────────────────────────
  it("initial state is ISSUED (0)", async function () {
    const { asset } = await deploy();
    expect(await asset.currentState()).to.equal(0n);
  });

  it("activate() transitions to ACTIVE (1)", async function () {
    const { asset } = await deploy();
    await asset.activate();
    expect(await asset.currentState()).to.equal(1n);
  });

  it("standardVersion() returns L3RS-1.0.0", async function () {
    const { asset } = await deploy();
    expect(await asset.standardVersion()).to.equal("L3RS-1.0.0");
  });

  // ── §6 Fees ────────────────────────────────────────────────────────────────
  it("feeRateBasisPoints() returns configured value", async function () {
    const { asset } = await deploy();
    expect(await asset.feeRateBasisPoints()).to.equal(100n);
  });

  // ── §9.6 Transfer ─────────────────────────────────────────────────────────
  it("transfer reverts when not ACTIVE", async function () {
    const { asset, user2 } = await deploy();
    await expect(
      asset.transfer(user2.address, 100n, ethers.randomBytes(32))
    ).to.be.revertedWith("L3RS1: not ACTIVE");
  });

  it("transfer succeeds when ACTIVE, parties VALID, oracle allows", async function () {
    const { asset, owner, user2 } = await deployActive();
    await asset.setIdentityStatus(owner.address, VALID);
    await asset.setIdentityStatus(user2.address, VALID);
    await asset.mint(owner.address, 1000n);
    await expect(asset.transfer(user2.address, 100n, ethers.randomBytes(32)))
      .to.emit(asset, "Transfer");
  });

  it("replay is rejected", async function () {
    const { asset, owner, user2 } = await deployActive();
    await asset.setIdentityStatus(owner.address, VALID);
    await asset.setIdentityStatus(user2.address, VALID);
    await asset.mint(owner.address, 1000n);
    const nonce = ethers.randomBytes(32);
    await asset.transfer(user2.address, 100n, nonce);
    await expect(
      asset.transfer(user2.address, 100n, nonce)
    ).to.be.revertedWith("L3RS1: replay");
  });

  // ── §17.8 Compliance/identity enforced before mutation ──────────────────────
  it("transfer reverts when sender identity is not VALID (fail-closed)", async function () {
    const { asset, user2 } = await deployActive();
    await asset.setIdentityStatus(user2.address, VALID); // receiver only
    await asset.mint(await asset.issuer(), 1000n);
    await expect(
      asset.transfer(user2.address, 100n, ethers.randomBytes(32))
    ).to.be.revertedWithCustomError(asset, "ComplianceBlocked");
  });

  it("transfer reverts when no compliance oracle is wired (fail-closed)", async function () {
    const ctx = await deploy();
    const { asset, owner, user2 } = ctx;
    await asset.activate();
    await asset.setIdentityOracle(owner.address);
    await asset.setIdentityStatus(owner.address, VALID);
    await asset.setIdentityStatus(user2.address, VALID);
    await asset.mint(owner.address, 1000n);
    await expect(
      asset.transfer(user2.address, 100n, ethers.randomBytes(32))
    ).to.be.revertedWithCustomError(asset, "ComplianceBlocked");
  });

  it("transfer reverts when the oracle blocks", async function () {
    const { asset, owner, user2, oracle } = await deployActive();
    await asset.setIdentityStatus(owner.address, VALID);
    await asset.setIdentityStatus(user2.address, VALID);
    await asset.mint(owner.address, 1000n);
    await oracle.setResult(false, ethers.encodeBytes32String("SANCTIONS"));
    await expect(
      asset.transfer(user2.address, 100n, ethers.randomBytes(32))
    ).to.be.revertedWithCustomError(asset, "ComplianceBlocked");
  });

  it("mint is issuer-gated", async function () {
    const { asset, user1 } = await deploy();
    await expect(
      asset.connect(user1).mint(user1.address, 1000n)
    ).to.be.revertedWithCustomError(asset, "NotIssuer");
  });

  // ── §4 Compliance view ──────────────────────────────────────────────────────
  it("checkCompliance returns false when not ACTIVE", async function () {
    const { asset, user1, user2 } = await deploy();
    const [allowed] = await asset.checkCompliance(user1.address, user2.address, 100n);
    expect(allowed).to.equal(false);
  });

  it("checkCompliance returns true when ACTIVE, parties VALID, oracle allows", async function () {
    const { asset, user1, user2 } = await deployActive();
    await asset.setIdentityStatus(user1.address, VALID);
    await asset.setIdentityStatus(user2.address, VALID);
    const [allowed] = await asset.checkCompliance(user1.address, user2.address, 100n);
    expect(allowed).to.equal(true);
  });

  it("checkCompliance returns false when identity missing (fail-closed)", async function () {
    const { asset, user1, user2 } = await deployActive();
    const [allowed, ruleId] = await asset.checkCompliance(user1.address, user2.address, 100n);
    expect(allowed).to.equal(false);
    expect(ruleId).to.equal(ethers.encodeBytes32String("ID_SENDER"));
  });

  // ── §10 Invariant I₁₁ ─────────────────────────────────────────────────────
  it("crossChainCertificateId is non-zero (Invariant I₁₁)", async function () {
    const { asset } = await deployActive();
    expect(await asset.crossChainCertificateId()).to.not.equal(ethers.ZeroHash);
  });
});
