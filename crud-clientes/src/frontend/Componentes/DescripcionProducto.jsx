import React, { useState } from 'react';
import { Modal, Button, InputGroup, FormControl } from 'react-bootstrap';
import { FaPlus, FaMinus } from 'react-icons/fa';
import './StylesComponent.css'; 

const DescripcionProducto = ({ product }) => {
  // Estado para manejar la visibilidad del modal
  const [showModal, setShowModal] = useState(false);
  const [quantity, setQuantity] = useState(1);

  const MAX_QUANTITY = 99999; // Establece un límite máximo de cantidad

  // Función para manejar el clic en "Añadir al pedido"
  const handleAgregarAlPedido = () => {
    const cartItem = {
      id: product.id_product,
      name: product.name,
      price: product.price,
      quantity: quantity,
      image: product.image
    };

    // Obtenemos el carrito actual del localStorage usando el id_customer
    const userId = localStorage.getItem('id_customer');
    const currentCart = JSON.parse(localStorage.getItem(`cart_${userId}`)) || [];

    // Buscamos si el producto ya esta en el carrito
    const existingItemIndex = currentCart.findIndex(item => item.id === cartItem.id);
    if (existingItemIndex !== -1) {
      // Si el producto ya esta en el carrito, actualizamos la cantidad
      currentCart[existingItemIndex].quantity += quantity;
    } else { 
      // Si el producto no esta en el carrito, lo agregamos
      currentCart.push(cartItem);
    }

    // Actualizamos el carrito en el localStorage
    localStorage.setItem(`cart_${userId}`, JSON.stringify(currentCart));
    setShowModal(true);
  }

  // Función para manejar el cierre del modal
  const handleCloseModal = () => {
    setShowModal(false);
  }

  const handleIncrement = () => {
    setQuantity(prevQuantity => Math.min(MAX_QUANTITY, prevQuantity + 1)); // Limita el incremento
  }

  const handleDecrement = () => {
    setQuantity(prevQuantity => Math.max(1, prevQuantity - 1));
  }

  return (
    <div className="detalle-producto-container">
      <div className="detalle-producto-img">
        <img src={product.image} alt={product.name} className="producto-imagen" />
      </div>
      <div className="detalle-producto-info">
        <h2 className="producto-titulo">{product.name}</h2>
        <p className="producto-descripcion">{product.description}</p>
        <div className="producto-detalles">
          <p><span className="detalle-etiqueta">Peso por Unidad:</span> {product.weight}g</p>
          <p><span className="detalle-etiqueta">Precio por Unidad:</span> Q{product.price}</p>
        </div>
        <div className="cantidad-selector mb-3">
          <label htmlFor="cantidad" className="detalle-etiqueta">Cantidad:</label>
          <InputGroup>
            <Button variant="outline-secondary" onClick={handleDecrement}>
              <FaMinus />
            </Button>
            <FormControl
              type="number"
              value={quantity}
              onChange={(e) => setQuantity(Math.max(1, Math.min(MAX_QUANTITY, parseInt(e.target.value))))} // Limita el valor ingresado
              min="1"
              max={MAX_QUANTITY} // Establece el límite máximo
              className="text-center"
            />
            <Button variant="outline-secondary" onClick={handleIncrement}>
              <FaPlus />
            </Button>
          </InputGroup>
          <small className="text-danger font-bold">Límite: {MAX_QUANTITY} unidades</small> {/* Mensaje de límite */}
        </div>
        <Button variant="primary" onClick={handleAgregarAlPedido} className="w-100">
          Añadir al pedido
        </Button>
        <Modal show={showModal} onHide={handleCloseModal} centered>
          <Modal.Header closeButton>
            <Modal.Title>Producto añadido</Modal.Title>
          </Modal.Header>
          <Modal.Body>El producto se ha añadido al pedido correctamente</Modal.Body>
          <Modal.Footer>
            <Button variant="primary" onClick={handleCloseModal}>
              Cerrar
            </Button>
          </Modal.Footer>
        </Modal>
      </div>
    </div>
  );
};

export default DescripcionProducto;