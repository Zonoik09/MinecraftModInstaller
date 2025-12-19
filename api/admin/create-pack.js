import { supabase } from "../../lib/supabase.js";
import crypto from "crypto";

export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).end();

  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).end();

  const token = authHeader.replace("Bearer ", "");

  const { data: userData, error: userError } =
    await supabase.auth.getUser(token);

  if (userError) return res.status(401).end();

  const { links } = req.body;

  const code = crypto.randomBytes(4).toString("hex");

  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + 7);

  const { error } = await supabase.from("packs").insert({
    code,
    links,
    expires_at: expiresAt.toISOString(),
    created_by: userData.user.id
  });

  if (error) {
    return res.status(400).json({ error: error.message });
  }

  res.json({ code, expires_at: expiresAt });
}
