// CREACION DE SERVIDOR EXPRESS QUE SE CONECTA A POSTGRESQL Y EXPONE UNA API PARA OBTENER DATOS

const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors({
    origin: 'http://localhost:3000',  // Cambia al puerto donde está corriendo tu frontend
    methods: ['POST', 'GET', 'OPTIONS', 'PUT'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));


// Conexión a la base de datos de PostgreSQL en Azure
const pool = new Pool({
    user: 'administradordb', // reemplaza con tu usuario de PostgreSQL en Azure
    host: 'servidor-db-cloud.postgres.database.azure.com', // reemplaza con la URL de tu servidor PostgreSQL en Azure
    database: 'Carnespa', // reemplaza con tu base de datos
    password: 'Estudio123', // reemplaza con tu contraseña
    port: 5432, // puerto por defecto de PostgreSQL
    ssl: {
        rejectUnauthorized: false // Asegúrate de usar SSL
    }
});


// Middleware para verificar el token
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).send({ auth: false, message: 'No token provided.' });
    
    jwt.verify(token, 'SECRET_KEY', (err, decoded) => {
        if (err) return res.status(500).send({ auth: false, message: 'Failed to authenticate token.' });
        
        req.userId = decoded.id;
        next();
    });
};

// Rutas de prueba
app.get('/', (req, res) => {
    res.send('Servidor de Express está funcionando');
});

// Ruta para obtener productos, con opción de filtrar por categoría
app.get('/api/products', async (req, res) => {
    const { category } = req.query; // Obtener la categoría de la query string
    let query = "SELECT * FROM product WHERE status = '1'";
    
    if (category) {
        // Agregar la condición de categoría si se proporciona
        query += " AND category = $1"; // Cambiar a un parámetro
    }

    try {
        const result = await pool.query(query, category ? [category] : []); // Pasar la categoría como parámetro
        console.log('Resultado:', result.rows); // Log del resultado
        res.json(result.rows);
    } catch (err) {
        console.error('Error en la consulta:', err.message); // Log del error
        res.status(500).send('Error en el servidor');
    }
});

// Ruta para obtener un producto por ID
app.get('/api/products/:id', async (req, res) => {
    const { id } = req.params;

    if (!id) {
        return res.status(400).json({ message: 'ID del producto es requerido' });
    }

    try {
        const result = await pool.query('SELECT * FROM product WHERE id_product = $1', [parseInt(id, 10)]);
        
        if (result.rows.length === 0) {
            return res.status(404).json({ message: 'Producto no encontrado' });
        }

        res.json(result.rows[0]);
    } catch (err) {
        console.error('Error en la consulta:', err.message);
        res.status(500).send('Error en el servidor');
    }
});


// Ruta para manejar la creación de pedidos
app.post('/api/orders', verifyToken, async (req, res) => {
    console.log('Recibiendo pedido:', req.body);
    console.log('Usuario ID:', req.userId); // Agregar este log
    
    const { nombre, direccion, municipio, comentarios, fechaPedidoiso, cartItems, total } = req.body;
  
    try {
        console.log('Iniciando transacción');
        await pool.query('BEGIN');
  
        console.log('Insertando en la tabla order');
        const orderResult = await pool.query(
            'INSERT INTO "order" (status, comment, date, total_price, id_customer) VALUES ($1, $2, $3, $4, $5) RETURNING id_order',
            ['sin ver', comentarios, fechaPedidoiso, total, req.userId]
        );
  
        const orderId = orderResult.rows[0].id_order;
        console.log('Orden creada con ID:', orderId);
  
        console.log('Insertando items del pedido');
        for (let item of cartItems) {
            await pool.query(
                'INSERT INTO order_item (amount, id_order, id_product, category) VALUES ($1, $2, $3, $4)',
                [item.amount, orderId, item.id_product, item.category]
            );
        }
  
        console.log('Confirmando transacción');
        await pool.query('COMMIT');
  
        res.status(200).json({ message: 'Pedido creado con éxito', orderId });
    } catch (error) {
        console.error('Error detallado:', error);
        await pool.query('ROLLBACK');
        res.status(500).json({ error: 'Error al procesar el pedido', details: error.message });
    }
});

  
// Ruta para obtener pedidos del usuario correspondiente
app.get('/api/orders', verifyToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM "order" WHERE id_customer = $1 ORDER BY date DESC', [req.userId]);
        res.json(result.rows);
    } catch (error) {
        console.error('Error al obtener los pedidos:', error);
        res.status(500).json({ error: 'Error al obtener los pedidos' });
    }
});

// Ruta para obtener los datos del usuario
app.get('/api/user', verifyToken, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                c.name, 
                c.e_mail, 
                c.address, 
                c.phone, 
                c.id_municipio, 
                c.id_zona,
                m.nombre_municipio AS municipio, 
                z.nombre_zona AS zona 
            FROM 
                customer c
            LEFT JOIN 
                municipio m ON c.id_municipio = m.id_municipio
            LEFT JOIN 
                zona z ON c.id_zona = z.id_zona
            WHERE 
                c.id_customer = $1`, [req.userId]);
        if (result.rows.length > 0) {
            res.json(result.rows[0]);
        } else {
            res.status(404).json({ error: 'Usuario no encontrado' });
        }
    } catch (error) {
        console.error('Error al obtener datos del usuario:', error.message);
        res.status(500).json({ error: 'Error al obtener datos del usuario', details: error.message });
    }
});

// Ruta paraObtener los detalles de un pedido específico
app.get('/api/orders/:id/items', async (req, res) => {
    const { id } = req.params;
    try {
        const result = await pool.query(`
            SELECT oi.*, p.name as product_name, p.price as unit_price
            FROM order_item oi
            JOIN product p ON oi.id_product = p.id_product
            WHERE oi.id_order = $1
        `, [id]);
        res.json(result.rows);
    } catch (error) {
        console.error('Error al obtener los detalles del pedido:', error);
        res.status(500).json({ error: 'Error al obtener los detalles del pedido' });
    }
});

// Endpoint en el backend para obtener las categorías
app.get('/api/categories', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM category_table WHERE status = $1', ['on-line']);
        res.json(result.rows); // Devuelve las categorías como un JSON
    } catch (error) {
        console.error(error.message);
        res.status(500).json({ error: 'Error al obtener categorías' });
    }
  });

// Ruta para actualizar los datos del usuario
app.put('/api/user', verifyToken, async (req, res) => {
    const { name, e_mail, address, phone, id_municipio, id_zona } = req.body;
    try {
        await pool.query(
            'UPDATE customer SET name = $1, e_mail = $2, address = $3, phone = $4, id_municipio = $5, id_zona = $6 WHERE id_customer = $7',
            [name, e_mail, address, phone, id_municipio, id_zona, req.userId]
        );
        res.status(200).json({ message: 'Datos actualizados con éxito' });
    } catch (error) {
        console.error('Error al actualizar los datos del usuario:', error);
        res.status(500).json({ error: 'Error al actualizar los datos del usuario' });
    }
});

// Ruta para el login del cliente
app.post('/login', async (req, res) => {
    const { e_mail, password } = req.body;

    try {
        const result = await pool.query(
            'SELECT * FROM customer WHERE e_mail = $1 and status = $2', [e_mail,'active']
        );
        const user = result.rows[0];

        if (!user) {
            return res.status(400).json({ error: 'Usuario no activado' });
        }

        // Verificar la contraseña
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(400).json({ error: 'Contraseña incorrecta' });
        }

        // Generar un token JWT
        const token = jwt.sign({ id: user.id_customer, e_mail: user.e_mail }, 'SECRET_KEY', { expiresIn: '1h' });

        res.json({ token, userId: user.id_customer });
    } catch (error) {
        console.error('Error al consultar la base de datos', error);
        res.status(500).json({ error: 'Error del servidor' });
    }
});

// Ruta para registrar un cliente nuevo
app.post('/register', async (req, res) => {
    const { name, e_mail, password, address, phone, id_municipio, id_zona } = req.body;

    try {
        // Verificar si el email ya está registrado
        const emailCheck = await pool.query('SELECT * FROM customer WHERE e_mail = $1', [e_mail]);
        if (emailCheck.rows.length > 0) {
            return res.status(400).json({ error: 'El email ya está registrado' });
        }

        // Encriptar la contraseña
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insertar el nuevo cliente
        const query = `
            INSERT INTO customer (name, e_mail, status, password, address, phone, id_municipio, id_zona)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING id_customer
        `;
        const values = [name, e_mail, 'active', hashedPassword, address, phone.toString(), id_municipio, id_zona];
        const result = await pool.query(query, values);

        const newUserId = result.rows[0].id_customer;

        // Generar un token JWT para el nuevo usuario
        const token = jwt.sign({ id: newUserId, e_mail }, 'SECRET_KEY', { expiresIn: '1h' });

        res.status(201).json({ message: 'Cliente registrado con éxito', token, userId: newUserId });
    } catch (err) {
        console.error('Error al registrar el cliente:', err);
        res.status(500).json({ error: 'Error al registrar el cliente', details: err.message });
    }
});

// Nueva ruta para obtener municipios y zonas
app.get('/api/municipios-y-zonas', async (req, res) => {
    try {
        const municipios = await pool.query('SELECT * FROM municipio'); // Obtener municipios
        const zonas = await pool.query('SELECT * FROM zona'); // Obtener zonas
        res.json({ municipios: municipios.rows, zonas: zonas.rows });
    } catch (error) {
        console.error('Error al obtener municipios y zonas:', error);
        res.status(500).json({ error: 'Error al obtener municipios y zonas' });
    }
});
// Iniciar el servidor
app.listen(PORT, () => {
    console.log(`Servidor corriendo en el puerto ${PORT}`);
});
