import './StylesComponent.css'; 
import React from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { FaUser, FaHome, FaBoxOpen, FaClipboardList } from 'react-icons/fa'; // Importa los iconos
import { TiShoppingCart, TiStarFullOutline } from "react-icons/ti";
import { NavLink } from 'react-router-dom'; 

const Navbar = () => {
    const navigate = useNavigate();

    const handleLogout = () => {
        const userId = localStorage.getItem('id_customer'); // Obtener el id del cliente
        localStorage.removeItem('id_customer');
        localStorage.removeItem('authToken');
        localStorage.removeItem(`cart_${userId}`); // Limpiar el carrito del usuario
        navigate('/login');
    };

    return (
        <nav className="navbar navbar-expand-lg">
            <div className="container-fluid">
                {/* Logotipo en la parte izquierda */}
                <NavLink className="navbar-brand" to="/">
                    <img src="https://productoscloud2.blob.core.windows.net/productos-pagina2/Logotipo.jpeg?sp=r&st=2024-11-17T00:59:42Z&se=2024-11-30T08:59:42Z&sv=2022-11-02&sr=b&sig=rgYA0OVsiTIrOEL9wso%2BEyRNOYABVXOP%2FGAzeKruMKQ%3D" alt="Logo" className="logo" />
                </NavLink>

                <button className="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNavAltMarkup" aria-controls="navbarNavAltMarkup" aria-expanded="false" aria-label="Toggle navigation">
                    <span className="navbar-toggler-icon"></span>
                </button>

                {/* Opciones centradas */}
                <div className="collapse navbar-collapse justify-content-center">
                    <div className="navbar-nav">
                        <NavLink className="nav-link text-white" to="/" activeClassName="active"><FaHome className="icon" /> Inicio</NavLink>
                        <NavLink className="nav-link text-white" to="/perfil" activeClassName="active"><FaUser className="icon" /> Perfil</NavLink>
                        <NavLink className="nav-link text-white" to="/productos" activeClassName="active"><FaBoxOpen className="icon" /> Productos</NavLink>
                        <NavLink className="nav-link text-white" to="/pedidos" activeClassName="active"><FaClipboardList className="icon" /> Pedidos</NavLink>
                        <button className="nav-link text-white" onClick={handleLogout}>Cerrar Sesión</button>
                    </div>
                </div>

                {/* Íconos de carrito y favoritos en la parte derecha */}
                <div className="navbar-icons">
                    <NavLink className="icons-link text-white" to="/carrito" activeClassName="active"><TiShoppingCart className="icon" /></NavLink>
                    <NavLink className="icons-link text-white" to="/favoritos" activeClassName="active"><TiStarFullOutline className="icon" /></NavLink>
                </div>
            </div>
        </nav>
    );
}

export default Navbar;