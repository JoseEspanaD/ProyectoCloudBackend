import './StylesPaginas.css';
import Navbar from '../Componentes/Navbar';
import NavbarProductos from '../Componentes/NavbarProductos';
import TarjetaProducto from '../Componentes/TarjetaProducto'; // Importamos el componente de tarjeta
import { useEffect, useState } from 'react';
import axios from 'axios';

const Productos = () => {
    const [products, setProducts] = useState([]); // Todos los productos
    const [filteredProducts, setFilteredProducts] = useState([]); // Productos filtrados por categoría
    const [activeCategory, setActiveCategory] = useState('Todos'); // Categoría activa

    // Obtener productos al cargar la página
    useEffect(() => {
        axios.get('http://localhost:5000/api/products')
            .then((response) => {
                setProducts(response.data);
                setFilteredProducts(response.data); // Mostrar todos los productos inicialmente
            })
            .catch((error) => {
                console.error('Error al obtener los productos:', error);
            });
    }, []);

    // Manejar el filtrado por categoría
    const handleCategoryChange = (category) => {
        setActiveCategory(category);
        if (category === 'Todos') {
            setFilteredProducts(products); // Mostrar todos los productos
        } else {
            const categoryMapping = {
                'Madurados': 'm',
                'Chorizos y Longanizas': 'cl', // Mapeo de la categoría
                'Embutidos': 'e',
                'Carnes': 'c'
            };
            const categoryCode = categoryMapping[category]; // Obtener el código de categoría correspondiente
            setFilteredProducts(products.filter(product => product.category === categoryCode)); // Filtrar por categoría
        }
    };

    return (
        <>
            <Navbar />
            {/* Pasamos la función de categoría al Navbar */}
            <NavbarProductos onCategoryChange={handleCategoryChange} activeCategory={activeCategory} />
            <div className="product-container">
                <div className="row row-cols-1 row-cols-md-4 g-4">
                    {filteredProducts.map((product, index) => (
                        <TarjetaProducto
                            key={index}
                            id={product.id_product} // ID del producto
                            image={product.image} // URL de la imagen
                            title={product.name} // Nombre del producto
                            price={`Q${product.price}`} // Precio
                            weight={`${product.weight}gr`} // Peso
                            category={product.category} // Incluir category
                        />
                    ))}
                </div>
            </div>
        </>
    );
};

export default Productos;
