import nextCoreWebVitals from "eslint-config-next/core-web-vitals"
import nextTypescript from "eslint-config-next/typescript"
import prettier from "eslint-config-prettier"

const config = [
  {
    ignores: ["coverage/**"],
  },
  ...nextCoreWebVitals,
  ...nextTypescript,
  {
    rules: {
      ...prettier.rules,
      "react-hooks/set-state-in-effect": "off",
      "react-hooks/purity": "off",
    },
  },
]

export default config
