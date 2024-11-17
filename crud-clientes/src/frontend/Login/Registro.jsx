import React, { useState } from 'react';
import axios from 'axios';
import { useNavigate, Link } from 'react-router-dom';
import { Container, Form, Button, Alert } from 'react-bootstrap';

const Registro = () => {
  const [e_mail, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const navigate = useNavigate();

  const handleLogin = async (e) => {
    e.preventDefault();
    try {
      const response = await axios.post('http://localhost:5000/login', { e_mail, password });
      const token = response.data.token;
      const userId = response.data.userId;

      localStorage.setItem('authToken', token);
      localStorage.setItem('id_customer', userId);

      setError('');
      setSuccess('Login exitoso');

      setTimeout(() => {
        navigate('/Inicio');
      }, 2000);
    } catch (err) {
      setError(err.response?.data?.error || 'Error al iniciar sesión');
      setSuccess('');
    }
  };

  return (
    <Container className="d-flex align-items-center justify-content-center" style={{ minHeight: "100vh" }}>
      <div className="w-100" style={{ maxWidth: "400px" }}>
        <h2 className="text-center mb-4" style={{ color: 'white' }}>Iniciar Sesión</h2>
        <Form onSubmit={handleLogin}>
          <Form.Group className="mb-3" controlId="formBasicEmail">
            <Form.Label style={{ color: 'white' }}>Email:</Form.Label>
            <Form.Control
              type="email"
              placeholder="Ingrese su email"
              value={e_mail}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
          </Form.Group>

          <Form.Group className="mb-3" controlId="formBasicPassword">
            <Form.Label style={{ color: 'white' }}>Contraseña:</Form.Label>
            <Form.Control
              type="password"
              placeholder="Ingrese su contraseña"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </Form.Group>

          <Button variant="primary" type="submit" className="w-100">
            Iniciar Sesión
          </Button>
        </Form>
        {error && <Alert variant="danger" className="mt-3">{error}</Alert>}
        {success && <Alert variant="success" className="mt-3">{success}</Alert>}
        <div className="text-center mt-3">
          <Link to="/register" style={{ color: 'white' }}>¿No tienes una cuenta? Regístrate aquí</Link>
        </div>
      </div>
    </Container>
  );
};

export default Registro;
