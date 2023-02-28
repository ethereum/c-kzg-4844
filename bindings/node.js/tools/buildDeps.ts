import fs from "fs";
import path from "path";

const REPO_ROOT = path.resolve(__dirname, "..", "..", "..");
const BINDINGS_ROOT = path.resolve(REPO_ROOT, "bindings", "node.js");
const DEPS = path.resolve(BINDINGS_ROOT, "deps");

const noCopyList = [/\.git$/, /\.o$/, /\.a$/];
async function recursivelyCopyFolder(source: string, target: string): Promise<Error[]> {
  const errors = [] as Error[];
  let stat = fs.statSync(source);
  if (!stat.isDirectory()) throw new Error("source is not a directory");
  if (!fs.existsSync(target)) {
    fs.mkdirSync(target);
  } else {
    stat = fs.statSync(target);
    if (!stat.isDirectory()) throw new Error("target is not a directory");
  }

  for (const name of fs.readdirSync(source)) {
    if (noCopyList.find((regxp) => regxp.test(name))) continue;
    const srcPath = path.resolve(source, name);
    const targetPath = path.resolve(target, name);
    if (fs.statSync(srcPath).isDirectory()) {
      errors.push(...(await recursivelyCopyFolder(srcPath, targetPath)));
    } else {
      if (fs.existsSync(targetPath)) {
        fs.unlinkSync(targetPath);
      }
      fs.copyFileSync(srcPath, targetPath);
    }
  }

  return errors;
}

(function buildDeps() {
  if (fs.existsSync(DEPS)) {
    fs.rmSync(DEPS, {recursive: true, force: true});
  }
  fs.mkdirSync(DEPS);
  recursivelyCopyFolder(path.resolve(REPO_ROOT, "blst"), path.resolve(DEPS, "blst"));
  recursivelyCopyFolder(path.resolve(REPO_ROOT, "src"), path.resolve(DEPS, "c-kzg"));
})();
