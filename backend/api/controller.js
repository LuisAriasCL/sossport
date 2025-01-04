const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('../api/db');
const router = express.Router();
const multer = require('multer');
const csvParser = require('csv-parser');
const fs = require('fs');

module.exports = (io) => {
  // Manejo del evento de conexión de Socket.IO
  io.on('connection', (socket) => {
    console.log('Nuevo cliente conectado');

    // Escucha el evento 'nuevo-mensaje' de los clientes
    socket.on('nuevo-mensaje', (mensaje) => {
      io.emit('nuevo-mensaje', mensaje); // Emite el nuevo mensaje a todos los clientes
    });

    // Manejo de desconexión
    socket.on('disconnect', () => {
      console.log('Cliente desconectado');
    });
  });




  router.post('/usuarios', async (req, res) => {
    const { nombre_usuario, correo, contrasena, telefono, ubicacion, foto_perfil } = req.body;

    try {
      // Verificar si el usuario ya existe
      const [existingUser] = await db.query('SELECT * FROM usuario WHERE correo = ?', [correo]);

      if (existingUser.length > 0) {
        return res.status(400).json({ message: 'El correo ya está registrado.' });
      }

      // Hashear la contraseña
      const hashedPassword = await bcrypt.hash(contrasena, 10);

      // Convertir la imagen base64 a Buffer, si tiene el prefijo 'data:image/...'
      let imageBuffer = null;
      if (foto_perfil) {
        const base64ImagePattern = /^data:image\/\w+;base64,/;
        if (base64ImagePattern.test(foto_perfil)) {
          const base64Data = foto_perfil.replace(base64ImagePattern, "");
          imageBuffer = Buffer.from(base64Data, 'base64');
        } else {
          imageBuffer = Buffer.from(foto_perfil, 'base64');
        }
      }

      await db.query(
        `INSERT INTO usuario (nombre_usuario, correo, rol, contrasena, telefono, ubicacion, foto_perfil, creado_en) 
       VALUES (?, ?, 'usuario', ?, ?, ?, ?, NOW())`,
        [nombre_usuario, correo, hashedPassword, telefono, ubicacion, imageBuffer]
      );

      return res.status(201).json({ message: 'Usuario creado exitosamente.' });
    } catch (error) {
      console.error('Error al registrar usuario:', error);
      return res.status(500).json({ message: 'Error interno del servidor.' });
    }
  });


  // Ruta para iniciar sesión
  router.post('/login', async (req, res) => {
    const { correo, contrasena } = req.body;

    try {
      // Buscar al usuario en la base de datos por correo
      const [users] = await db.query('SELECT * FROM usuario WHERE correo = ?', [correo]);

      // Si no se encuentra el usuario
      if (!users || users.length === 0) {
        return res.status(401).json({ message: 'Credenciales incorrectas.' });
      }

      const foundUser = users[0];

      // Verificar si el usuario está suspendido
      if (foundUser.fecha_suspension && new Date(foundUser.fecha_suspension) > new Date()) {
        return res.status(403).json({ message: `Tu cuenta está suspendida hasta el ${foundUser.fecha_suspension}. Por acomulación de reportes.` });
      }

      // Comparar la contraseña ingresada con la contraseña almacenada
      const isValid = await bcrypt.compare(contrasena, foundUser.contrasena);

      // Si la contraseña es incorrecta
      if (!isValid) {
        return res.status(401).json({ message: 'Credenciales incorrectas.' });
      }

      // Crear el token de autenticación
      const token = jwt.sign({ id: foundUser.id_usuario }, 'clave_unica', { expiresIn: '1h' });

      // Responder con éxito y los datos del usuario
      return res.status(200).json({
        message: 'Inicio de sesión exitoso',
        token,
        user: {
          id_usuario: foundUser.id_usuario,
          nombre_usuario: foundUser.nombre_usuario,
          correo: foundUser.correo,
          rol: foundUser.rol,
        },
      });
    } catch (error) {
      console.error('Error al iniciar sesión:', error);
      return res.status(500).json({ message: 'Error interno del servidor.' });
    }
  });


  return router;
}
