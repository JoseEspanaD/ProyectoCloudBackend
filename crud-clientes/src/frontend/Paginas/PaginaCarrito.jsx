import React, { useState, useEffect } from 'react';
import Navbar from '../Componentes/Navbar';
import CarritoCompras from '../Componentes/CarritoCompras';
import ConfirmacionPedido from '../Componentes/ConfirmacionPedido';
import axios from 'axios';
import './StylesPaginas.css';

const PaginaCarrito = () => {
  const [showConfirmacion, setShowConfirmacion] = useState(false);
  const [cartItems, setCartItems] = useState([]);
  const [total, setTotal] = useState(0);
  const [userId, setUserId] = useState(null);

  useEffect(() => {
    const userId = localStorage.getItem('id_customer'); // Obtener el ID del cliente desde localStorage
    const storedCart = JSON.parse(localStorage.getItem(`cart_${userId}`)) || [];
    setCartItems(storedCart);
    const newTotal = storedCart.reduce((sum, item) => sum + item.price * item.quantity, 0);
    setTotal(newTotal);
  }, [userId]);

  const handleProcederPedido = (items, totalCarrito) => {
    if (totalCarrito >= 300) {
      setCartItems(items);
      setTotal(totalCarrito);
      setShowConfirmacion(true);
    } else {
      alert('El monto mínimo para realizar un pedido es de Q300');
    }
  };

  const handleConfirmPedido = async (pedidoData) => {
    try {
      const response = await axios.post('http://localhost:5000/api/orders', pedidoData);
      if (response.status === 200) {
        alert('Pedido realizado con éxito');
        // Vaciar el carrito
        const userId = localStorage.getItem('id_customer'); // Obtener el ID del cliente
        localStorage.removeItem(`cart_${userId}`); // Limpiar el carrito del usuario
        setCartItems([]); // Vaciar el estado del carrito
        setTotal(0); // Reiniciar el total
      }
    } catch (error) {
      console.error('Error al realizar el pedido:', error);
    }
  };

  return (
    <>
      <Navbar />
      <CarritoCompras 
        onProcederPedido={handleProcederPedido} 
        cartItems={cartItems}
        setCartItems={setCartItems}
        total={total}
        setTotal={setTotal}
      />
      <ConfirmacionPedido 
        show={showConfirmacion}
        onHide={() => setShowConfirmacion(false)}
        cartItems={cartItems}
        total={total}
        onConfirm={handleConfirmPedido}
      />
    </>
  );
};

export default PaginaCarrito;
