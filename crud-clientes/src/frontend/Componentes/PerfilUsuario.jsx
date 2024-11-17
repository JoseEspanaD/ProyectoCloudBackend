import React, { useEffect, useState } from 'react';
import { FaUserCircle } from 'react-icons/fa'; // Icono de perfil
import './StylesComponent.css';
import 'bootstrap/dist/css/bootstrap.min.css'; // Importar Bootstrap

const PerfilUsuario = () => {
    const [userData, setUserData] = useState({});
    const [isEditing, setIsEditing] = useState(false);
    const [formData, setFormData] = useState({
        name: '',
        e_mail: '',
        address: '',
        phone: '',
        id_municipio: '',
        id_zona: ''
    });
    const [alertMessage, setAlertMessage] = useState('');
    const [alertType, setAlertType] = useState(''); // 'success' o 'danger'
    const [municipios, setMunicipios] = useState([]); // Estado para municipios
    const [zonas, setZonas] = useState([]); // Estado para zonas

    useEffect(() => {
        // Función para obtener los datos del usuario
        const fetchUserData = async () => {
            const response = await fetch('http://localhost:5000/api/user', {
                method: 'GET',
                headers: {
                    'Authorization': localStorage.getItem('authToken'),
                },
            });
            const data = await response.json();
            setUserData(data);
            setFormData(data); // Inicializa el formulario con los datos del usuario
        };

        // Función para obtener municipios y zonas
        const fetchMunicipiosYZonas = async () => {
            const response = await fetch('http://localhost:5000/api/municipios-y-zonas');
            const data = await response.json();
            setMunicipios(data.municipios);
            setZonas(data.zonas);
        };

        fetchUserData();
        fetchMunicipiosYZonas();
    }, []);

    const handleEditToggle = () => {
        setIsEditing(!isEditing);
        setAlertMessage('');
        setAlertType('');
    };

    const handleChange = (e) => {
        setFormData({ ...formData, [e.target.name]: e.target.value });
    };

    const validateFormData = (data) => {
        const errors = {};
        if (!data.name) {
            errors.name = "El nombre es obligatorio.";
        }
        if (!data.e_mail || !/\S+@\S+\.\S+/.test(data.e_mail)) {
            errors.e_mail = "El correo electrónico no es válido.";
        }
        if (!data.phone || !/^\d+$/.test(data.phone)) {
            errors.phone = "El teléfono debe contener solo números.";
        }
        // Agregar más validaciones según sea necesario
        return errors;
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        const errors = validateFormData(formData);
        if (Object.keys(errors).length > 0) {
            setAlertMessage(Object.values(errors).join('\n'));
            setAlertType('danger'); // Tipo de alerta para errores
            return;
        }
        
        const response = await fetch('http://localhost:5000/api/user', {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': localStorage.getItem('authToken'),
            },
            body: JSON.stringify(formData),
        });
        if (response.ok) {
            setUserData(formData);
            setIsEditing(false);
            setAlertMessage('Los datos se han editado correctamente.'); // Mensaje de éxito
            setAlertType('success'); // Tipo de alerta para éxito
            
            // Desaparecer el mensaje después de 4 segundos
            setTimeout(() => {
                setAlertMessage('');
                setAlertType('');
            }, 4000);
        } else {
            const errorData = await response.json();
            console.error('Error al actualizar:', errorData);
            setAlertMessage('Error al actualizar los datos.'); // Mensaje de error
            setAlertType('danger');
        }
    };

    return (
        <div className="user-profile">
            {alertMessage && (
                <div className={`alert alert-${alertType}`} role="alert">
                    {alertMessage}
                </div>
            )}
            <div className="profile-header">
                <FaUserCircle className="profile-icon" />
                <h2>Perfil de Usuario</h2>
            </div>
            <form onSubmit={handleSubmit}>
                <div className="profile-info">
                    <label>Nombre:&nbsp;&nbsp;</label>
                    {isEditing ? (
                        <input type="text" name="name" value={formData.name} onChange={handleChange} />
                    ) : (
                        <span>{userData.name}</span>
                    )}
                </div>
                <div className="profile-info">
                    <label>Correo:&nbsp;&nbsp;</label>
                    {isEditing ? (
                        <input type="email" name="e_mail" value={formData.e_mail} onChange={handleChange} />
                    ) : (
                        <span>{userData.e_mail}</span>
                    )}
                </div>
                <div className="profile-info">
                    <label>Dirección:&nbsp;&nbsp;</label>
                    {isEditing ? (
                        <input type="text" name="address" value={formData.address} onChange={handleChange} />
                    ) : (
                        <span>{userData.address}</span>
                    )}
                </div>
                <div className="profile-info">
                    <label>Teléfono:&nbsp;&nbsp;</label>
                    {isEditing ? (
                        <input type="text" name="phone" value={formData.phone} onChange={handleChange} />
                    ) : (
                        <span>{userData.phone}</span>
                    )}
                </div>
                <div className="profile-info">
                    <label>Municipio:&nbsp;&nbsp;</label>
                    {isEditing ? (
                        <select name="id_municipio" value={formData.id_municipio} onChange={handleChange}>
                            <option value="">Seleccione un municipio</option>
                            {municipios.map((mun) => (
                                <option key={mun.id_municipio} value={mun.id_municipio}>
                                    {mun.nombre_municipio}
                                </option>
                            ))}
                        </select>
                    ) : (
                        <span>{userData.municipio}</span>
                    )}
                </div>
                <div className="profile-info">
                    <label>Zona:&nbsp;&nbsp;</label>
                    {isEditing ? (
                        <select name="id_zona" value={formData.id_zona} onChange={handleChange}>
                            <option value="">Seleccione una zona</option>
                            {zonas.map((z) => (
                                <option key={z.id_zona} value={z.id_zona}>
                                    {z.nombre_zona}
                                </option>
                            ))}
                        </select>
                    ) : (
                        <span>{userData.zona}</span>
                    )}
                </div>
                <button type="button" className="btn-editar-personalizado" onClick={handleEditToggle}>
                    {isEditing ? 'Cancelar' : 'Editar'}
                </button>
                {isEditing && <button type="submit" className="btn-guardar-personalizado">Guardar Cambios</button>}
            </form>
        </div>
    );
};

export default PerfilUsuario;