import React, { useState, useEffect } from 'react';
import { Table, Button, InputGroup, FormControl } from 'react-bootstrap';
import { FaTrash, FaPlus, FaMinus, FaShoppingCart } from 'react-icons/fa';
import './StylesComponent.css';


const CarritoCompras = ({ onProcederPedido }) => {
  const [cartItems, setCartItems] = useState([]);
  const [total, setTotal] = useState(0);
  const userId = localStorage.getItem('id_customer');
  const MAX_QUANTITY = 99999;

  useEffect(() => {
    const cart = JSON.parse(localStorage.getItem(`cart_${userId}`)) || [];
    setCartItems(cart);
    calculateTotal(cart);
  }, [userId]);

  const calculateTotal = (items) => {
    const newTotal = items.reduce((sum, item) => sum + item.price * item.quantity, 0);
    setTotal(newTotal);
  };

  const handleQuantityChange = (id, newQuantity) => {
    const updatedCart = cartItems.map(item => 
      item.id === id ? { ...item, quantity: Math.max(1, Math.min(MAX_QUANTITY, newQuantity)) } : item
    );
    setCartItems(updatedCart);
    localStorage.setItem(`cart_${userId}`, JSON.stringify(updatedCart));
    calculateTotal(updatedCart);
  };

  const handleRemoveItem = (id) => {
    const updatedCart = cartItems.filter(item => item.id !== id);
    setCartItems(updatedCart);
    localStorage.setItem(`cart_${userId}`, JSON.stringify(updatedCart));
    calculateTotal(updatedCart);
  };

  return (
    <div className="carrito-container">
      <br />
      <h2 className="titulo-historial">Carrito de Compras</h2>
      {cartItems.length === 0 ? (
        <div className="text-center">
          <h4 className="mb-4" style={{color: 'white'}}>
            <FaShoppingCart /> Tu carrito está vacío... ¡Agrega algunos productos!
          </h4>
        </div>
      ) : (
        <div className="tabla-carrito">
          <Table striped bordered hover responsive>
            <thead>
              <tr>
                <th>Producto</th>
                <th>Cantidad</th>
                <th>Precio Unitario</th>
                <th>Subtotal</th>
                <th>Acciones</th>
              </tr>
            </thead>
            <tbody>
              {cartItems.map((item) => (
                <tr key={item.id}>
                  <td>
                  <img src={item.image} alt={item.name} style={{width: '50px', marginRight: '10px'}} />
                    {item.name}
                  </td>
                  <td>
                    <InputGroup>
                      <Button variant="outline-secondary" onClick={() => handleQuantityChange(item.id, item.quantity - 1)}>
                        <FaMinus />
                      </Button>
                      <FormControl
                        type="number"
                        value={item.quantity}
                        onChange={(e) => handleQuantityChange(item.id, parseInt(e.target.value))}
                        max={MAX_QUANTITY}
                        min="1"
                        className="text-center"
                      />
                      <Button variant="outline-secondary" onClick={() => handleQuantityChange(item.id, item.quantity + 1)}>
                        <FaPlus />
                      </Button>
                    </InputGroup>
                  </td>
                  <td>Q{item.price}</td>
                  <td>Q{(item.price * item.quantity).toFixed(2)}</td>
                  <td>
                    <Button variant="danger" onClick={() => handleRemoveItem(item.id)}>
                      <FaTrash />
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
          <div className="carrito-total text-end">
            <strong><h4 style={{color: 'white'}}>Monto mínimo de compra: Q300</h4></strong>
            <strong><h4 style={{color: 'white'}}>Total a pagar: Q{total.toFixed(2)}</h4></strong>
          </div>
          <div className="text-end">
            <Button 
              variant="primary" 
              className="mt-3"
              onClick={() => onProcederPedido(cartItems, total)}
              disabled={total < 300}
            >
              Proceder con el Pedido
            </Button>
          </div>
        </div>
      )}
    </div>
  );
};

export default CarritoCompras;