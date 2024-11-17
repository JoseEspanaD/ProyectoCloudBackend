// TarjetaProducto.jsx
import { FaArrowCircleRight, FaStar } from 'react-icons/fa';
import { useNavigate } from 'react-router-dom';
import { useState, useEffect } from 'react';
import { Modal, Button } from 'react-bootstrap';
import './StylesComponent.css';

const TarjetaProducto = ({ id, image, title, price, weight, category }) => {
    const navigate = useNavigate();
    const [isFavorite, setIsFavorite] = useState(false);
    const [showModal, setShowModal] = useState(false);
    const [modalMessage, setModalMessage] = useState('');

    useEffect(() => {
        const userId = localStorage.getItem('id_customer');
        const favorites = JSON.parse(localStorage.getItem(`favorites_${userId}`)) || [];
        setIsFavorite(favorites.some(item => item.id === id));
    }, [id]);

    const handleRedirect = () => {
        navigate(`/DetalleProducto/${id}`);
    };

    const handleFavoriteToggle = () => {
        const userId = localStorage.getItem('id_customer');
        const favorites = JSON.parse(localStorage.getItem(`favorites_${userId}`)) || [];
        let updatedFavorites;

        if (isFavorite) {
            updatedFavorites = favorites.filter(item => item.id !== id);
            setModalMessage('El producto se ha quitado de favoritos');
        } else {
            updatedFavorites = [...favorites, { id, image, name: title, price, category }];
            setModalMessage('El producto se ha añadido a favoritos');
        }

        localStorage.setItem(`favorites_${userId}`, JSON.stringify(updatedFavorites));
        setIsFavorite(!isFavorite);
        setShowModal(true);
    };

    const handleCloseModal = () => {
        setShowModal(false);
    };

    return (
        <div className="col">
            <div className="card product-card">
                <img src={image} className="card-img-top" alt={title} />
                <div className="card-body">
                    <h5 className="card-title">{title}</h5>
                    <p className="card-text">Precio: {price}</p>
                    <p className="card-text">Peso: {weight}</p>
                    <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
                        <FaStar
                            onClick={handleFavoriteToggle}
                            size={24}
                            style={{
                                cursor: 'pointer',
                                marginLeft: '10px',
                                color: isFavorite ? 'gold' : 'gray',
                            }}
                        />
                        <FaArrowCircleRight
                            className="arrow-icon"
                            onClick={handleRedirect}
                            size={24}
                            style={{ cursor: 'pointer' }}
                        />
                    </div>
                </div>
            </div>

            <Modal show={showModal} onHide={handleCloseModal} centered>
                <Modal.Header closeButton>
                    <Modal.Title>Favoritos</Modal.Title>
                </Modal.Header>
                <Modal.Body>{modalMessage}</Modal.Body>
                <Modal.Footer>
                    <Button variant="primary" onClick={handleCloseModal}>
                        Cerrar
                    </Button>
                </Modal.Footer>
            </Modal>
        </div>
    );
};

export default TarjetaProducto;
