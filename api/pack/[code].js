import { supabase } from '../../lib/supabase.js';

export default async function handler(req, res) {
  const { code } = req.query;

  const { data, error } = await supabase
    .from('packs')
    .select('*')
    .eq('code', code)
    .single();

  if (error || !data) return res.status(404).json({ message: 'Pack not found' });

  return res.json(data);
}
