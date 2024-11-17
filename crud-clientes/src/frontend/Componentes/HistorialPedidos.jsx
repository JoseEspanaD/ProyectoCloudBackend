// HistorialPedidos.jsx
import React, { useState, useEffect } from 'react';
import { Table, Button, Modal } from 'react-bootstrap';
import { FaListUl } from "react-icons/fa";
import axios from 'axios';
import FiltroPedidos from './FiltroPedidos';
import './StylesComponent.css';

const HistorialPedidos = () => {
  const [pedidos, setPedidos] = useState([]);
  const [showModal, setShowModal] = useState(false);
  const [pedidoSeleccionado, setPedidoSeleccionado] = useState(null);
  const [detallesPedido, setDetallesPedido] = useState([]);
  const [showFiltro, setShowFiltro] = useState(false);
  const [selectedOption, setSelectedOption] = useState('');
  const [pedidosOriginales, setPedidosOriginales] = useState([]);

  useEffect(() => {
    const fetchPedidos = async () => {
      try {
        const token = localStorage.getItem('authToken');
        const response = await axios.get('http://localhost:5000/api/orders', {
          headers: { 'Authorization': token }
        });
        setPedidos(response.data);
        setPedidosOriginales(response.data);
      } catch (error) {
        console.error('Error al obtener los pedidos:', error);
      }
    };

    fetchPedidos();
  }, []);

  const handleVerDescripcion = async (pedido) => {
    setPedidoSeleccionado(pedido);
    try {
      const token = localStorage.getItem('authToken');
      const response = await axios.get(`http://localhost:5000/api/orders/${pedido.id_order}/items`, {
        headers: { 'Authorization': token }
      });
      setDetallesPedido(response.data);
      setShowModal(true);
    } catch (error) {
      console.error('Error al obtener los detalles del pedido:', error);
    }
  };

  const handleSort = (order) => {
    let sortedPedidos;
    if (order === 'sinVer') {
      sortedPedidos = pedidosOriginales.filter(pedido => pedido.status === 'sin ver');
    } else if (order === 'pendientes') {
      sortedPedidos = pedidosOriginales.filter(pedido => pedido.status === 'pendiente');
    } else if (order === 'enProceso') {
      sortedPedidos = pedidosOriginales.filter(pedido => pedido.status === 'en proceso');
    } else if (order === 'fechaAsc') {
      sortedPedidos = [...pedidosOriginales].sort((a, b) => new Date(a.date) - new Date(b.date));
    } else if (order === 'fechaDesc') {
      sortedPedidos = [...pedidosOriginales].sort((a, b) => new Date(b.date) - new Date(a.date));
    } else if (order === 'precioAsc') {
      sortedPedidos = [...pedidosOriginales].sort((a, b) => a.total_price - b.total_price);
    } else if (order === 'precioDesc') {
      sortedPedidos = [...pedidosOriginales].sort((a, b) => b.total_price - a.total_price);
    } else if (order === 'entregados') {
      sortedPedidos = pedidosOriginales.filter(pedido => pedido.status === 'entregado');
    }
    
    if (sortedPedidos.length > 0) {
      setPedidos(sortedPedidos);
    } else {
      setPedidos([]);
    }
    
    setSelectedOption(order);
    setShowFiltro(false);
  };

  return (
    <div className="historial-pedidos-container">
      <br />
      <h2 className="titulo-historial">Historial de Pedidos</h2>
      <div className="organizar-pedidos-container">
        <div className="organizar-pedidos" onClick={() => setShowFiltro(true)}>
          <span>Organizar Pedidos</span>
          <div className="organizar-icon">
            <FaListUl />
          </div>
        </div>
      </div>
      <Table striped bordered hover responsive>
        <thead>
          <tr>
            <th>#</th>
            <th>Fecha</th>
            <th>Estado</th>
            <th>Precio Total</th>
            <th>Acción</th>
          </tr>
        </thead>
        <tbody>
          {pedidos.map((pedido, index) => (
            <tr key={pedido.id_order}>
              <td>{index + 1}</td>
              <td>{new Date(pedido.date).toLocaleDateString()}</td>
              <td>{pedido.status}</td>
              <td>Q {pedido.total_price}</td>
              <td>
                <Button variant="info" onClick={() => handleVerDescripcion(pedido)}>
                  Detalle
                </Button>
              </td>
            </tr>
          ))}
        </tbody>
      </Table>

      <FiltroPedidos
        show={showFiltro}
        handleClose={() => setShowFiltro(false)}
        handleSort={handleSort}
        selectedOption={selectedOption}
      />

      <Modal show={showModal} onHide={() => setShowModal(false)} size="lg">
        <Modal.Header closeButton>
          <Modal.Title>Detalles del Pedido con ID #{pedidoSeleccionado?.id_order} Asignado</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <Table striped bordered hover>
            <thead>
              <tr>
                <th>Producto</th>
                <th>Precio Unitario</th>
                <th>Cantidad</th>
                <th>Total</th>
              </tr>
            </thead>
            <tbody>
              {detallesPedido.map((item) => (
                <tr key={item.id_item}>
                  <td>{item.product_name}</td>
                  <td>Q{item.unit_price}</td>
                  <td>{item.amount}</td>
                  <td>Q{(item.unit_price * item.amount).toFixed(2)}</td>
                </tr>
              ))}
            </tbody>
          </Table>
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={() => setShowModal(false)}>
            Cerrar
          </Button>
        </Modal.Footer>
      </Modal>
    </div>
  );
};

export default HistorialPedidos;
