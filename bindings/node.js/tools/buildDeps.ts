import fs from "fs";
import {resolve} from "path";

const REPO_ROOT = resolve(__dirname, "..", "..", "..");
const BINDINGS_ROOT = resolve(REPO_ROOT, "bindings", "node.js");
const DEPS = resolve(BINDINGS_ROOT, "deps");

function copyDir(src: string, dest: string): void {
  fs.mkdirSync(dest);
  fs.cpSync(src, dest, {recursive: true});
}

(function buildDeps() {
  if (fs.existsSync(DEPS)) {
    fs.rmSync(DEPS, {recursive: true, force: true});
  }
  fs.mkdirSync(DEPS);
  copyDir(resolve(REPO_ROOT, "blst"), resolve(DEPS, "blst"));
  copyDir(resolve(REPO_ROOT, "src"), resolve(DEPS, "c-kzg"));
})();
