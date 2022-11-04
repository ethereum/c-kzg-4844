import typescript from "@rollup/plugin-typescript";

export default {
  input: "kzg.ts",
  output: {
    file: "dist/index.js",
    format: "cjs",
  },
  plugins: [typescript()],
};
