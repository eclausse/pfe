import App from "./app";
import AccessController from "./access";
import SupplierController from "./supplier";
import UserController from "./user";

const controllers = [
  new UserController(),
  new SupplierController(),
  new AccessController(),
];

const app = new App(
  controllers,
  8080,
);

app.listen();