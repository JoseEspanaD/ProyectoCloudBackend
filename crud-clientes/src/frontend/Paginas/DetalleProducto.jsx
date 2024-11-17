import { useParams, useNavigate } from 'react-router-dom';
import { useEffect, useState } from 'react';
import axios from 'axios';
import Navbar from '../Componentes/Navbar';
import NavbarProductos from '../Componentes/NavbarProductos';
import DescripcionProducto from '../Componentes/DescripcionProducto';

const DetalleProducto = () => {
    const { id } = useParams();
    const navigate = useNavigate();
    const [product, setProduct] = useState(null);
    const [activeCategory, setActiveCategory] = useState('Todos');

    useEffect(() => {
        axios.get(`http://localhost:5000/api/products/${id}`)
            .then((response) => {
                setProduct(response.data);
            })
            .catch((error) => {
                console.error('Error al obtener los detalles del producto:', error);
            });
    }, [id]);

    const handleCategoryChange = (category) => {
        setActiveCategory(category);
        navigate('/productos', { state: { category } });
    };

    if (!product) {
        return <p>Cargando detalles del producto...</p>;
    }

    return (
        <>
            <Navbar />
            <NavbarProductos onCategoryChange={handleCategoryChange} activeCategory={activeCategory} />
            <DescripcionProducto product={product} />
        </>
    );
};

export default DetalleProducto;
