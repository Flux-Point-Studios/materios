#!/usr/bin/env node

import { Command } from "commander";
import { runPipeline } from "./pipeline.js";

const program = new Command();

program
  .name("receipt-builder")
  .description("Build integrity receipts from JSONL audit traces")
  .version("0.1.0")
  .requiredOption("--in <path>", "Input JSONL file path")
  .requiredOption("--out <path>", "Output directory path")
  .option(
    "--chunk-size <bytes>",
    "Target chunk size in bytes",
    "65536",
  )
  .option("--encrypt-key <hex>", "AES-256 encryption key as hex string")
  .option("--skip-poseidon", "Skip Poseidon hash computation", false)
  .action(async (opts) => {
    try {
      const receipt = await runPipeline({
        input: opts.in,
        output: opts.out,
        chunkSize: parseInt(opts.chunkSize, 10),
        encryptKey: opts.encryptKey,
        skipPoseidon: opts.skipPoseidon,
      });

      console.log("\n=== Receipt Builder Summary ===");
      console.log(`Receipt ID:      ${receipt.receiptId}`);
      console.log(`Content Hash:    ${receipt.contentHash}`);
      console.log(`Base Root:       ${receipt.baseRootSha256}`);
      console.log(
        `ZK Root:         ${receipt.zkRootPoseidon ?? "(skipped)"}`,
      );
      console.log(`Schema Hash:     ${receipt.schemaHash}`);
      console.log(`Observed At:     ${new Date(receipt.observedAtMillis).toISOString()}`);
      console.log(`\nOutput written to: ${opts.out}`);
    } catch (err) {
      console.error("Pipeline failed:", err);
      process.exit(1);
    }
  });

program.parse();
