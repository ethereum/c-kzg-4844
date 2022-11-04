import typescript from "@rollup/plugin-typescript";

export default {
  input: "kzg.ts",
  output: {
    dir: "dist",
    format: "cjs",
  },
  plugins: [typescript()],
};
