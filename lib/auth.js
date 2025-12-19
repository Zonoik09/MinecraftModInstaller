import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET;

export function requireAuth(req) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    throw new Error('No token provided');
  }

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    throw new Error('Invalid authorization format');
  }

  const token = parts[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    return decoded; // { id, username, exp, iat }
  } catch (err) {
    throw new Error('Invalid or expired token');
  }
}
