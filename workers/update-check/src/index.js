// The update-check Worker's platform binding; the logic is in logic.js so
// `node --test` covers it without a Workers runtime.
import { handle } from "./logic.js";

export default {
  async fetch(request, env) {
    return handle(request, env, fetch, request.cf);
  },
};
