// server.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const fs = require('fs').promises;
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'tu_secreto_super_seguro_cambialo_en_produccion';

// Middleware
app.use(cors());
app.use(express.json());

// Directorios para almacenar datos
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const MODPACKS_FILE = path.join(DATA_DIR, 'modpacks.json');

// ============================================
// FUNCIONES DE BASE DE DATOS (JSON)
// ============================================

// Inicializar archivos de datos
async function initializeDataFiles() {
  try {
    // Crear directorio 'data' si no existe
    await fs.mkdir(DATA_DIR, { recursive: true });
    
    // Crear archivo de usuarios si no existe
    try {
      await fs.access(USERS_FILE);
    } catch {
      await fs.writeFile(USERS_FILE, JSON.stringify([], null, 2));
      console.log('✅ Archivo users.json creado');
    }
    
    // Crear archivo de modpacks si no existe
    try {
      await fs.access(MODPACKS_FILE);
    } catch {
      await fs.writeFile(MODPACKS_FILE, JSON.stringify({}, null, 2));
      console.log('✅ Archivo modpacks.json creado');
    }

    console.log('📁 Base de datos inicializada correctamente');
  } catch (error) {
    console.error('❌ Error inicializando archivos:', error);
  }
}

// Leer usuarios desde el archivo JSON
async function readUsers() {
  try {
    const data = await fs.readFile(USERS_FILE, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    console.error('Error leyendo usuarios:', error);
    return [];
  }
}

// Escribir usuarios en el archivo JSON
async function writeUsers(users) {
  try {
    await fs.writeFile(USERS_FILE, JSON.stringify(users, null, 2));
  } catch (error) {
    console.error('Error escribiendo usuarios:', error);
    throw error;
  }
}

// Leer modpacks desde el archivo JSON
async function readModpacks() {
  try {
    const data = await fs.readFile(MODPACKS_FILE, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    console.error('Error leyendo modpacks:', error);
    return {};
  }
}

// Escribir modpacks en el archivo JSON
async function writeModpacks(modpacks) {
  try {
    await fs.writeFile(MODPACKS_FILE, JSON.stringify(modpacks, null, 2));
  } catch (error) {
    console.error('Error escribiendo modpacks:', error);
    throw error;
  }
}

// ============================================
// MIDDLEWARE DE AUTENTICACIÓN
// ============================================

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Token no proporcionado' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Token inválido o expirado' });
    }
    req.user = user;
    next();
  });
}

// ============================================
// RUTAS DE AUTENTICACIÓN
// ============================================

// Registro de usuario
app.post('/api/admin/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Validaciones
    if (!username || !email || !password) {
      return res.status(400).json({ message: 'Todos los campos son obligatorios' });
    }

    if (username.length < 3) {
      return res.status(400).json({ message: 'El usuario debe tener al menos 3 caracteres' });
    }

    if (password.length < 6) {
      return res.status(400).json({ message: 'La contraseña debe tener al menos 6 caracteres' });
    }

    // Validar formato de email básico
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ message: 'Email inválido' });
    }

    // Leer usuarios existentes
    const users = await readUsers();

    // Verificar si el usuario ya existe
    if (users.find(u => u.username === username)) {
      return res.status(400).json({ message: 'El usuario ya existe' });
    }

    if (users.find(u => u.email === email)) {
      return res.status(400).json({ message: 'El email ya está registrado' });
    }

    // Hash de la contraseña (10 rondas de salt)
    const hashedPassword = await bcrypt.hash(password, 10);

    // Crear nuevo usuario
    const newUser = {
      id: Date.now().toString(),
      username,
      email,
      password: hashedPassword,
      createdAt: new Date().toISOString()
    };

    users.push(newUser);
    await writeUsers(users);

    console.log(`✅ Usuario registrado: ${username}`);

    res.status(201).json({ 
      message: 'Usuario registrado exitosamente',
      username: newUser.username 
    });
  } catch (error) {
    console.error('❌ Error en registro:', error);
    res.status(500).json({ message: 'Error interno del servidor' });
  }
});

// Login de usuario
app.post('/api/admin/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ message: 'Usuario y contraseña son obligatorios' });
    }

    // Buscar usuario
    const users = await readUsers();
    const user = users.find(u => u.username === username);

    if (!user) {
      return res.status(401).json({ message: 'Usuario o contraseña incorrectos' });
    }

    // Verificar contraseña
    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) {
      return res.status(401).json({ message: 'Usuario o contraseña incorrectos' });
    }

    // Generar token JWT (expira en 24 horas)
    const token = jwt.sign(
      { id: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    console.log(`✅ Login exitoso: ${username}`);

    res.json({ 
      token,
      username: user.username,
      message: 'Login exitoso'
    });
  } catch (error) {
    console.error('❌ Error en login:', error);
    res.status(500).json({ message: 'Error interno del servidor' });
  }
});

// ============================================
// RUTAS DE MODPACKS
// ============================================

// Obtener modpack por código (PÚBLICO - no requiere autenticación)
app.get('/api/modpack/:code', async (req, res) => {
  try {
    const { code } = req.params;

    // Validar que el código tenga 6 dígitos
    if (!/^\d{6}$/.test(code)) {
      return res.status(400).json({ message: 'El código debe tener 6 dígitos numéricos' });
    }

    const modpacks = await readModpacks();
    const modpack = modpacks[code];

    if (!modpack) {
      return res.status(404).json({ message: 'Modpack no encontrado' });
    }

    console.log(`📦 Modpack solicitado: ${code} (${modpack.mods.length} mods)`);

    res.json({ 
      code,
      mods: modpack.mods,
      modsCount: modpack.mods.length,
      createdAt: modpack.createdAt,
      createdBy: modpack.createdBy
    });
  } catch (error) {
    console.error('❌ Error obteniendo modpack:', error);
    res.status(500).json({ message: 'Error interno del servidor' });
  }
});

// Crear/actualizar modpack (REQUIERE AUTENTICACIÓN)
app.post('/api/admin/modpack', authenticateToken, async (req, res) => {
  try {
    const { code, mods } = req.body;

    // Validaciones
    if (!code || !mods) {
      return res.status(400).json({ message: 'Código y mods son obligatorios' });
    }

    if (!/^\d{6}$/.test(code)) {
      return res.status(400).json({ message: 'El código debe tener 6 dígitos numéricos' });
    }

    if (!Array.isArray(mods) || mods.length === 0) {
      return res.status(400).json({ message: 'Debes proporcionar al menos un mod' });
    }

    // Validar que todos los elementos sean URLs válidas
    const urlPattern = /^https?:\/\/.+/;
    const invalidUrls = mods.filter(url => typeof url !== 'string' || !urlPattern.test(url));
    
    if (invalidUrls.length > 0) {
      return res.status(400).json({ 
        message: 'Todas las URLs deben ser válidas y comenzar con http:// o https://',
        invalidCount: invalidUrls.length
      });
    }

    // Leer modpacks existentes
    const modpacks = await readModpacks();
    const isUpdate = !!modpacks[code];

    // Crear o actualizar modpack
    modpacks[code] = {
      mods,
      createdBy: req.user.username,
      createdAt: modpacks[code]?.createdAt || new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    await writeModpacks(modpacks);

    console.log(`✅ Modpack ${isUpdate ? 'actualizado' : 'creado'}: ${code} por ${req.user.username}`);

    res.status(200).json({ 
      message: `Modpack ${isUpdate ? 'actualizado' : 'guardado'} exitosamente`,
      code,
      modsCount: mods.length
    });
  } catch (error) {
    console.error('❌ Error guardando modpack:', error);
    res.status(500).json({ message: 'Error interno del servidor' });
  }
});

// Eliminar modpack (REQUIERE AUTENTICACIÓN)
app.delete('/api/admin/modpack/:code', authenticateToken, async (req, res) => {
  try {
    const { code } = req.params;

    if (!/^\d{6}$/.test(code)) {
      return res.status(400).json({ message: 'El código debe tener 6 dígitos' });
    }

    const modpacks = await readModpacks();

    if (!modpacks[code]) {
      return res.status(404).json({ message: 'Modpack no encontrado' });
    }

    // Verificar que el modpack pertenezca al usuario
    if (modpacks[code].createdBy !== req.user.username) {
      return res.status(403).json({ message: 'No tienes permiso para eliminar este modpack' });
    }

    delete modpacks[code];
    await writeModpacks(modpacks);

    console.log(`🗑️ Modpack eliminado: ${code} por ${req.user.username}`);

    res.json({ message: 'Modpack eliminado exitosamente' });
  } catch (error) {
    console.error('❌ Error eliminando modpack:', error);
    res.status(500).json({ message: 'Error interno del servidor' });
  }
});

// Listar todos los modpacks del usuario (REQUIERE AUTENTICACIÓN)
app.get('/api/admin/modpacks', authenticateToken, async (req, res) => {
  try {
    const modpacks = await readModpacks();
    
    // Filtrar modpacks del usuario autenticado
    const userModpacks = Object.entries(modpacks)
      .filter(([_, modpack]) => modpack.createdBy === req.user.username)
      .map(([code, modpack]) => ({
        code,
        modsCount: modpack.mods.length,
        createdAt: modpack.createdAt,
        updatedAt: modpack.updatedAt
      }));

    res.json({ 
      modpacks: userModpacks,
      total: userModpacks.length
    });
  } catch (error) {
    console.error('❌ Error listando modpacks:', error);
    res.status(500).json({ message: 'Error interno del servidor' });
  }
});

// ============================================
// RUTAS ADICIONALES
// ============================================

// Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'Servidor funcionando correctamente',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// Ruta raíz
app.get('/', (req, res) => {
  res.json({
    message: 'Minecraft Mod Installer API',
    version: '1.0.0',
    endpoints: {
      auth: {
        register: 'POST /api/admin/register',
        login: 'POST /api/admin/login'
      },
      modpacks: {
        get: 'GET /api/modpack/:code (público)',
        create: 'POST /api/admin/modpack (autenticado)',
        delete: 'DELETE /api/admin/modpack/:code (autenticado)',
        list: 'GET /api/admin/modpacks (autenticado)'
      }
    }
  });
});

// Manejo de rutas no encontradas
app.use((req, res) => {
  res.status(404).json({ message: 'Ruta no encontrada' });
});

// ============================================
// INICIO DEL SERVIDOR
// ============================================

async function startServer() {
  try {
    await initializeDataFiles();
    
    app.listen(PORT, () => {
      console.log('\n' + '='.repeat(50));
      console.log('🚀 SERVIDOR INICIADO CORRECTAMENTE');
      console.log('='.repeat(50));
      console.log(`🌐 URL: http://localhost:${PORT}`);
      console.log(`📁 Datos: ${DATA_DIR}`);
      console.log(`🔐 JWT Secret: ${JWT_SECRET.substring(0, 10)}...`);
      console.log('\n📋 ENDPOINTS DISPONIBLES:');
      console.log('   Autenticación:');
      console.log('   POST   /api/admin/register');
      console.log('   POST   /api/admin/login');
      console.log('\n   Modpacks:');
      console.log('   GET    /api/modpack/:code (público)');
      console.log('   POST   /api/admin/modpack (autenticado)');
      console.log('   DELETE /api/admin/modpack/:code (autenticado)');
      console.log('   GET    /api/admin/modpacks (autenticado)');
      console.log('\n   Utilidad:');
      console.log('   GET    /api/health');
      console.log('   GET    /');
      console.log('='.repeat(50) + '\n');
    });
  } catch (error) {
    console.error('❌ Error iniciando servidor:', error);
    process.exit(1);
  }
}

startServer();