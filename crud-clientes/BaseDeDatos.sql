CREATE TABLE order_item (
    id_articulo INTEGER NOT NULL,
    amount INTEGER,
    id_order INTEGER NOT NULL,
    id_customer INTEGER NOT NULL,
    id_product INTEGER NOT NULL,
    PRIMARY KEY (id_articulo, id_order, id_customer, id_product)
);

DROP TABLE IF EXISTS product;

CREATE TABLE product (
    id_product INTEGER NOT NULL PRIMARY KEY,
    name CHARACTER VARYING(50),
    description CHARACTER VARYING(250),
    weight INTEGER,
    price NUMERIC(10, 2),
    status CHARACTER VARYING(50),
	category CHARACTER VARYING(50), 
    image TEXT 
);

SELECT CURRENT_USER;


-----------AGREGAR PRODUCTOS---------------:
INSERT INTO product (id_product, name, description, weight, price, status, category, image) VALUES
(1, 'Chorizo Rosca Polaca', 'Delicioso chorizo en forma de herradura basado en una receta internacional.', 420, 25.00, '1', 'cl', 'https://i.postimg.cc/zDM1bNMW/Polaca.png'),
(2, 'Chorizo Chipotle', 'Delicioso chorizo en forma de herradura con un toque especial de picante chipotle.', 420, 25.00, '1', 'cl', 'https://i.postimg.cc/76ZJgXT5/Chipotle.png'),
(3, 'Chorizo Ahumado Tecpán', 'Delicioso chorizo basado en una receta tradicional de la comunidad Tecpaneca.', 420, 25.00, '1', 'cl', 'https://i.postimg.cc/sX3fS2qK/Tecpan.png'),
(4, 'Longaniza Tipo Tecpán', 'Deliciosa longaniza basada en una receta tradicional de la comunidad Tecpaneca.', 420, 25.00, '1', 'cl', 'https://i.postimg.cc/Gm04tbLg/Longaniza-Tecpan.png'),
(5, 'Jamón Curado Cataluña', 'Jamón finamente seleccionado de res, curado y madurado artesanalmente.', 100, 22.00, '1', 'm', 'https://i.postimg.cc/66nxrZC0/curado-cataluna.png'),
(6, 'Jamón Curado Marsella', 'Jamón finamente seleccionado de cerdo, curado y madurado artesanalmente.', 100, 16.00, '1', 'm', 'https://i.postimg.cc/x8hkVzTg/curado-marsella.png'),
(7, 'Carpaccio de Res Aderezado', 'Jamón curado y aderezado con receta de la casa.', 100, 22.00, '1', 'm', 'https://i.postimg.cc/VvCfMHmB/aderezado-res.png'),
(8, 'Carpaccio de Cerdo Aderezado', 'Jamón curado y aderezado con receta de la casa.', 100, 20.00, '1', 'm', 'https://i.postimg.cc/0N4rwS7v/aderezado-cerdo.png'),
(9, 'Pepperoni', 'Elaborado con una receta tradicional para un comportamiento a alta temperatura, especial para pizzas.', 454, 24.00, '1', 'e', 'https://i.postimg.cc/fRC5h9b7/peperoni.png'),
(10, 'Chorizo Precocido de Libra', 'Chorizo de 10 unidades enfocado para el mercado tradicional.', 454, 19.00, '1', 'e', 'https://i.postimg.cc/vm61tJC1/chorizo-precocido.png'),
(11, 'Longaniza Precocida de Libra', 'Longaniza de 10 unidades enfocado para el mercado tradicional.', 454, 19.00, '1', 'e', 'https://i.postimg.cc/6qx1QNxC/longaniza-precocida.png'),
(12, 'Roast Beef Gourmet', 'Carne de res finamente seleccionada.', 115, 17.00, '1', 'e', 'https://i.postimg.cc/Qxy1gJVy/Roast-Beef.png')
;


select * from product;


