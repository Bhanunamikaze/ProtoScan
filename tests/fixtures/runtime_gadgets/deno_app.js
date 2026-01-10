async function runTasks(payload) {
  await Deno.run({ cmd: ["whoami"], env: payload.env }).status();
  const command = new Deno.Command("ls", { args: payload.args || [] });
  await command.spawn().status();
  await Deno.makeTempDir({ dir: payload.tempDir });
  await Deno.writeTextFile(payload.targetPath, payload.contents || "owned");
}

export { runTasks };
