import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Container, Form, Button, Alert } from 'react-bootstrap';

const RegisterForm = () => {
    const [name, setName] = useState('');
    const [password, setPassword] = useState('');
    const [email, setEmail] = useState('');
    const [address, setAddress] = useState('');
    const [phone, setPhone] = useState('');
    const [municipio, setMunicipio] = useState('');
    const [zona, setZona] = useState('');
    const [message, setMessage] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [registrationSuccess, setRegistrationSuccess] = useState(false);
    const [municipios, setMunicipios] = useState([]);
    const [zonas, setZonas] = useState([]);
    const navigate = useNavigate();

    useEffect(() => {
        const fetchMunicipiosYZonas = async () => {
            const response = await fetch('http://localhost:5000/api/municipios-y-zonas');
            const data = await response.json();
            setMunicipios(data.municipios);
            setZonas(data.zonas);
        };

        fetchMunicipiosYZonas();
    }, []);

    const handleSubmit = async (e) => {
        e.preventDefault();
        if (password !== confirmPassword) {
            setMessage('Las contraseñas no coinciden');
            return;
        }
        const formData = { 
            name, 
            password, 
            e_mail: email, 
            address, 
            phone, 
            id_municipio: municipio,
            id_zona: zona
        };
    
        try {
            const response = await fetch('http://localhost:5000/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(formData),
            });
    
            const result = await response.json();
            if (response.ok) {
                localStorage.removeItem('authToken');
                localStorage.removeItem('id_customer');
                
                localStorage.setItem('authToken', result.token);
                localStorage.setItem('id_customer', result.userId);
                
                setRegistrationSuccess(true);
                setMessage('Registro exitoso!');
            } else {
                setMessage(result.error || 'Error en el registro');
                console.error('Detalles del error:', result.details);
            }
        } catch (error) {
            setMessage('Error en el registro');
            console.error('Error completo:', error);
        }
    };

    return (
        <Container className="d-flex align-items-center justify-content-center" style={{ minHeight: "100vh" }}>
            <div className="w-100" style={{ maxWidth: "400px" }}>
                {registrationSuccess ? (
                    <>
                        <h2 className="text-center mb-4" style={{ color: 'white' }}>¡Registro Exitoso!</h2>
                        <Alert variant="success" className="mt-3">Tu cuenta ha sido creada con éxito. Puedes iniciar sesión ahora.</Alert>
                        <Button variant="primary" onClick={() => navigate('/login')} className="w-100">
                            Ir a Iniciar Sesión
                        </Button>
                    </>
                ) : (
                    <>
                        <h2 className="text-center mb-4" style={{ color: 'white' }}>Registro de Nuevo Cliente</h2>
                        <Form onSubmit={handleSubmit}>
                            <Form.Group className="mb-3" controlId="formName">
                                <Form.Label style={{ color: 'white' }}>Nombre Completo:</Form.Label>
                                <Form.Control
                                    type="text"
                                    value={name}
                                    onChange={(e) => setName(e.target.value)}
                                    required
                                />
                            </Form.Group>

                            <Form.Group className="mb-3" controlId="formEmail">
                                <Form.Label style={{ color: 'white' }}>Email:</Form.Label>
                                <Form.Control
                                    type="email"
                                    value={email}
                                    onChange={(e) => setEmail(e.target.value)}
                                    required
                                />
                            </Form.Group>

                            <Form.Group className="mb-3" controlId="formPassword">
                                <Form.Label style={{ color: 'white' }}>Contraseña:</Form.Label>
                                <Form.Control
                                    type="password"
                                    value={password}
                                    onChange={(e) => setPassword(e.target.value)}
                                    required
                                />
                            </Form.Group>

                            <Form.Group className="mb-3" controlId="formConfirmPassword">
                                <Form.Label style={{ color: 'white' }}>Confirmar Contraseña:</Form.Label>
                                <Form.Control
                                    type="password"
                                    value={confirmPassword}
                                    onChange={(e) => setConfirmPassword(e.target.value)}
                                    required
                                />
                            </Form.Group>

                            <Form.Group className="mb-3" controlId="formAddress">
                                <Form.Label style={{ color: 'white' }}>Dirección:</Form.Label>
                                <Form.Control
                                    type="text"
                                    value={address}
                                    onChange={(e) => setAddress(e.target.value)}
                                    required
                                />
                            </Form.Group>

                            <Form.Group className="mb-3" controlId="formPhone">
                                <Form.Label style={{ color: 'white' }}>Teléfono:</Form.Label>
                                <Form.Control
                                    type="tel"
                                    value={phone}
                                    onChange={(e) => setPhone(e.target.value)}
                                    required
                                />
                            </Form.Group>

                            <Form.Group className="mb-3" controlId="formMunicipio">
                                <Form.Label style={{ color: 'white' }}>Municipio:</Form.Label>
                                <Form.Select
                                    value={municipio}
                                    onChange={(e) => setMunicipio(e.target.value)}
                                    required
                                >
                                    <option value="">Seleccione un municipio</option>
                                    {municipios.length > 0 ? (
                                        municipios.map((mun) => (
                                            <option key={mun.id_municipio} value={mun.id_municipio}>{mun.nombre_municipio}</option>
                                        ))
                                    ) : (
                                        <option value="" disabled>No hay municipios disponibles</option>
                                    )}
                                </Form.Select>
                            </Form.Group>

                            <Form.Group className="mb-3" controlId="formZona">
                                <Form.Label style={{ color: 'white' }}>Zona:</Form.Label>
                                <Form.Select
                                    value={zona}
                                    onChange={(e) => setZona(e.target.value)}
                                    required
                                >
                                    <option value="">Seleccione una zona</option>
                                    {zonas.length > 0 ? (
                                        zonas.map((z) => (
                                            <option key={z.id_zona} value={z.id_zona}>{z.nombre_zona}</option>
                                        ))
                                    ) : (
                                        <option value="" disabled>No hay zonas disponibles</option>
                                    )}
                                </Form.Select>
                            </Form.Group>

                            <Button variant="primary" type="submit" className="w-100">
                                Registrarse
                            </Button>
                        </Form>
                        {message && <Alert variant={message.includes('exitoso') ? 'success' : 'danger'} className="mt-3">{message}</Alert>}
                    </>
                )}
            </div>
        </Container>
    );
};

export default RegisterForm;