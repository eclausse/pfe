import App from "./app";
import AccessController from "./access";
import SupplierController from "./supplier";
import UserController from "./user";
import AdminController from "./administation";
import FileController from "./file";

const controllers = [
  new UserController(),
  new SupplierController(),
  new AccessController(),
  new AdminController(),
  new FileController(),
];

const app = new App(
  controllers,
  8080,
);

app.listen();