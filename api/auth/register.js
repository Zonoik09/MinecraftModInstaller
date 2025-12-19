import { supabase } from "../../lib/supabase.js";

export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).end();

  const { email, password, username } = req.body;

  const { data, error } = await supabase.auth.admin.createUser({
    email,
    password,
    email_confirm: true
  });

  if (error) {
    return res.status(400).json({ error: error.message });
  }

  await supabase.from("profiles").insert({
    id: data.user.id,
    username
  });

  res.json({ ok: true });
}
