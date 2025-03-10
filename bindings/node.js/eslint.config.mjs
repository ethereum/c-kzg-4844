import { fixupConfigRules, fixupPluginRules } from "@eslint/compat";
import typescriptEslint from "@typescript-eslint/eslint-plugin";
import _import from "eslint-plugin-import";
import node from "eslint-plugin-node";
import prettier from "eslint-plugin-prettier";
import globals from "globals";
import tsParser from "@typescript-eslint/parser";
import path from "node:path";
import { fileURLToPath } from "node:url";
import js from "@eslint/js";
import { FlatCompat } from "@eslint/eslintrc";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const compat = new FlatCompat({
    baseDirectory: __dirname,
    recommendedConfig: js.configs.recommended,
    allConfig: js.configs.all
});

export default [...fixupConfigRules(compat.extends(
    "eslint:recommended",
    "plugin:import/errors",
    "plugin:import/warnings",
    "plugin:import/typescript",
    "plugin:@typescript-eslint/recommended",
)), {
    plugins: {
        "@typescript-eslint": fixupPluginRules(typescriptEslint),
        import: fixupPluginRules(_import),
        node,
        prettier,
    },

    languageOptions: {
        globals: {
            ...globals.browser,
            ...globals.node,
            ...globals.mocha,
            BigInt: true,
        },

        parser: tsParser,
        ecmaVersion: 10,
        sourceType: "commonjs",

        parserOptions: {
            project: "./tsconfig.json",
        },
    },

    settings: {
        "import/core-modules": [
            "node:child_process",
            "node:crypto",
            "node:fs",
            "node:os",
            "node:path",
            "node:util",
        ],
    },

    rules: {
        "prettier/prettier": ["error", {}],
        "constructor-super": "off",
        "@typescript-eslint/await-thenable": "error",
        "@typescript-eslint/explicit-function-return-type": ["off"],
        "@typescript-eslint/member-ordering": "error",
        "@typescript-eslint/no-explicit-any": "error",
        "@typescript-eslint/no-var-requires": "off",

        "@typescript-eslint/no-unused-vars": ["error", {
            varsIgnorePattern: "^_",
        }],

        "@typescript-eslint/ban-ts-comment": "warn",
        "@typescript-eslint/no-use-before-define": "off",
        "@typescript-eslint/no-floating-promises": "error",
        "@typescript-eslint/no-require-imports": "off",

        "@typescript-eslint/explicit-member-accessibility": ["error", {
            accessibility: "no-public",
        }],

        "@typescript-eslint/no-unsafe-call": "off",
        "@typescript-eslint/no-unsafe-return": "off",

        "import/no-extraneous-dependencies": ["error", {
            devDependencies: false,
            optionalDependencies: false,
            peerDependencies: false,
        }],

        "import/no-duplicates": "off",
        "new-parens": "error",
        "no-caller": "error",
        "no-bitwise": "off",
        "no-cond-assign": "error",
        "no-consecutive-blank-lines": 0,
        "no-console": "warn",
        "no-var": "error",
        "object-curly-spacing": ["error", "never"],
        "object-literal-sort-keys": 0,
        "no-prototype-builtins": 0,
        "prefer-const": "error",
        quotes: ["error", "double"],
    },
}, {
    files: ["**/test/**/*.ts"],

    rules: {
        "import/no-extraneous-dependencies": "off",
        "@typescript-eslint/no-explicit-any": "off",
    },
}, {
    files: ["**/*.ts", "**/*.mts", "**/*.cts", "**/*.tsx"],

    rules: {
        "@typescript-eslint/explicit-function-return-type": ["error", {
            allowExpressions: true,
        }],
    },
}];