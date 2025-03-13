import Controller from "./controller";
import { Request, Response, Router } from "express";
import { Database } from "sqlite3";
import { log } from "console";
import { createHash, randomUUID, UUID } from "crypto";
import axios from "axios";
import * as fs from "fs";
import * as path from "path";
import dotenv from "dotenv";
import rateLimit from "express-rate-limit";

// Load environment variables from .env file
dotenv.config();

class FileController implements Controller {
  static path = "/upload-link-service";
  router: Router;
  db_name = "vuln.db";

  static upload_limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 1000, 
    message: "Too many uploads from this IP, please try again later.",
  });


  constructor() {
    this.router = Router();
    this.router.post(FileController.path, this.post);
    this.router.post(FileController.path + "/fix", FileController.upload_limiter, this.post_fix);
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
    const sql: string = `SELECT * FROM file_data`;
    let files: FileEntry[] = [];
    await FileController.run_query(sql).then((rows: any) =>
      rows.forEach((row: any) => {
        files.push(new FileEntry(row.uuid, row.url, row.content));
      })
    );
    res.send(JSON.stringify(files));
  }

    async get_all_by_uuid(req: Request, res: Response) {
        if (req.body.uuid === undefined) {
            res.send("Please provide a uuid");
            return;
        }

        const sql: string = `SELECT * FROM file_data WHERE uuid = ?`;
        let files: FileEntry[] = [];
        await FileController.run_query(sql, [req.body.uuid]).then((rows: any) =>
            rows.forEach((row: any) => {
              files.push(new FileEntry(row.uuid, row.url, row.content));
            })
        );

        console.log(
        "[INFO][GET] get alls on " + FileController.path,
        );
        res.send(JSON.stringify(files));     
    }

    async post(req: Request, res: Response) {
        const url = req.body.url;
        if (!url) {
          return res.status(400).send("URL is required");
        }

        const uid = req.body.uid;
        if (!uid) {
          return res.status(400).send("UUID is required");
        }

        try {
            const response = await axios({
                url,
                method: "GET",
                headers: {
                'x-backend-token': `${process.env.BACKEND_TOKEN}`
                }
            });
            const sql: string = `INSERT INTO file_data (uuid, url, content) VALUES ("${uid}", "${url}", "${response.status}")`;
            await FileController.run_query(sql);
            console.log(
              "[INFO][POST] insert on " + FileController.path,
            );
            res.send(response.data)
        } catch (e){
            res.send(JSON.stringify("Invalid URL"))
        }
    }

    async post_fix(req: Request, res: Response) {
      const url: string = req.body.url;
      if (!url) {
        return res.status(400).send("URL is required");
      }

      const uid = req.body.uid;
      if (!uid) {
        return res.status(400).send("UUID is required");
      }

      /* ------- URL sanitization -------- */
      // Restrict to http and https protocols
      const allowed_protocols = ["http://", "https://"]; // Allow list of protocols
      if (!allowed_protocols.some((protocol) => url.includes(protocol))) {
        return res.status(400).send("Invalid URL: Only HTTP and HTTPS protocols are allowed");
      }

      // Loopback address restriction via deny list
      // Loopback address can be represented in multiple ways 
      // This is not a good practice! Malicious user can bypass this check!
      const loopback_representations = ["localhost", "/^127\.\d+\.\d+\.\d+$/g", "/^0:0:0:0:0:0:0:1$/g", "/^::1$/g", "::ffff:7f00:1"];
      if (loopback_representations.some((representation) => url.includes(representation))) {
        return res.status(400).send("Invalid URL: Loopback address not allowed");
      }
      
      // Restrict to only certain domains
      const allowed_domains = ["trustedwebsite.com", "cdn.safeimages.com"];
      if (!allowed_domains.some((domain) => url.includes(domain))) {
        return res.status(400).send("Invalid URL: Domain not allowed");
      }

      try {
          const response = await axios({
              url,
              method: "GET",
              headers: {
              'x-backend-token': `${process.env.BACKEND_TOKEN}`
              },
              maxRedirects: 0, // Disable redirection
          });

          const sql: string = `INSERT INTO file_data (uuid, url, content) VALUES ("${uid}", "${url}", "${response.status}")`;
          await FileController.run_query(sql);
          console.log("[INFO][POST] insert on " + FileController.path + "/fix");

          res.status(200).send(response.data)
      } catch (e){
          res.status(400).send(JSON.stringify("Invalid URL: Impossible to fetch the content"))
      }
  }
}

export default FileController;


class FileEntry {
  uuid: UUID;
  url: string;
  content: string;

  constructor(
    uuid: UUID,
    url: string,
    content: string
  ) {
    this.uuid = uuid;
    this.url = url;
    this.content = content;
  }
}