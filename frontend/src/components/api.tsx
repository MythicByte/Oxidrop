import type { paths } from "@/api/schema";
import createClient from "openapi-fetch";

export const client = createClient<paths>({
  credentials: "include", // keeps the __Host-session cookie behavior you had before
});
