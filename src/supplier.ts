import Controller from "./controller";
import { Request, Response, Router } from "express";
import { Database } from "sqlite3";
import { log } from "console";

class SupplierController implements Controller {
  static path = "/supplier";
  router: Router;
  db_name = "vuln.db";

  constructor() {
    this.router = Router();
    this.router.get(SupplierController.path, this.get); /* Vulnérabilité SQLi */
    this.router.get(SupplierController.path + "/fix", this.get_with_parameterized_query); /* Pas de vulnérabilité SQLi*/
    this.router.post(SupplierController.path, this.post);
  }

  static run_query(query: string, params: any = []) {
    const db = new Database("vuln.db");
    return new Promise((resolve, reject) =>
      db.all(query, params, (err, rows) => {
        if (err) {
          console.log(err);
        }
        resolve(rows);
      })
    );
  }

  async get(req: Request, res: Response) {
    // Vérification de la présence du paramètre name 
    if (req.body.name === undefined) {
      res.send("Please provide a name");
      return;
    }
    
    // Création de la requête SQL en concaténant le paramètre name
    const sql: string = `SELECT rowid, * FROM supplier WHERE name = "${req.body.name}"`; // SQL Injection possible
    // Récupération des fournisseurs en fonction de la requête
    let suppliers: String[][] = [];
    await SupplierController.run_query(sql).then((rows: any) =>
      rows.forEach((row: any) => {
        suppliers.push([row.name, row.address]);
      })
    );

    console.log(
      "[INFO][GET] get alls on " + SupplierController.path,
    );
    // Envoi de la réponse
    res.send(JSON.stringify(suppliers));  
  }

  async get_with_parameterized_query(req: Request, res: Response) {
    // Vérification de la présence du paramètre name 
    if (req.body.name === undefined) {
      res.send("Please provide a name");
      return;
    }
    
    // Création de la requête SQL parametriée
    const sql: string = `SELECT rowid, * FROM supplier WHERE name = ?`; // SQL Injection impossible
    const params = [req.body.name];

    // Récupération des fournisseurs en fonction de la requête
    let suppliers: String[][] = [];
    // Passage de la requête et des paramètres à la fonction run_query
    await SupplierController.run_query(sql, params).then((rows: any) =>
      rows.forEach((row: any) => {
        suppliers.push([row.name, row.address]);
      })
    );

    console.log(
      "[INFO][GET] get alls on " + SupplierController.path,
    );
    // Envoi de la réponse
    res.send(JSON.stringify(suppliers));  
  }

  async post(req: Request, res: Response) {
    const supplier = new SupplierEntry(
      0,
      req.body.name,
      req.body.address
    );
    const sql = `INSERT INTO supplier (name, address) VALUES ('${supplier.name}', '${supplier.address}')`;
    await SupplierController.run_query(sql);
    console.log(
      "[INFO][POST] insert on " + SupplierController.path,
    );
    res.send("Supplier added successfully");
  }
}

export default SupplierController;

class Supplier {
  name: string;
  address: string;
  constructor(
    name: string,
    address: string
  ) {
    this.name = name;
    this.address = address;
  }
}

class SupplierEntry {
  id: number;
  name: string;
  address: string;

  constructor(
    id: number,
    name: string,
    address: string
  ) {
    this.id = id;
    this.name = name;
    this.address = address;
  }
}