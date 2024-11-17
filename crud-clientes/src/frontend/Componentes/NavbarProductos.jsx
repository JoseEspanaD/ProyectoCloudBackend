import React, { useState, useEffect } from 'react';
import axios from 'axios';

const NavbarProductos = ({ onCategoryChange, activeCategory }) => {
    const [categories, setCategories] = useState(['Todos']); // Inicia con 'Todos'

    useEffect(() => {
        // Obtener categorías del backend
        const fetchCategories = async () => {
            try {
                const response = await axios.get('http://localhost:5000/api/categories');
                const fetchedCategories = response.data.map(category => category.name);
                setCategories(['Todos', ...fetchedCategories]); // Agregar 'Todos' al inicio
                console.log("Categorías obtenidas:", fetchedCategories);
                
            } catch (error) {
                console.error("Error al obtener las categorías:", error);
            }
        };

        fetchCategories();
    }, []);

    return (
        <nav className="navbar navbar-productos navbar-expand-lg">
            <div className="container-fluid">
                <div className="collapse navbar-collapse justify-content-center" id="navbarNavAltMarkup">
                    <div className="navbar-nav">
                        {categories.map((category) => (
                            <div
                                key={category}
                                className={`nav-link text-white ${activeCategory === category ? 'active' : ''}`}
                                onClick={() => onCategoryChange(category)} // Actualiza la categoría activa
                                style={{ cursor: 'pointer' }}
                            >
                                {category}
                            </div>
                        ))}
                    </div>
                </div>
            </div>
        </nav>
    );
};

export default NavbarProductos;
