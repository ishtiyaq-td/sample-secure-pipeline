// app.test.js
// Deliberately thin test coverage to trigger the 80% coverage gate in the pipeline

const request = require("supertest");
const app = require("./app");

describe("GET /search", () => {
  it("returns 200 for a basic search", async () => {
    const res = await request(app).get("/search?q=hello");
    expect(res.statusCode).toBe(200);
  });

  // Missing test: XSS payload is not tested — coverage tool will flag
  // the unsanitised branch as uncovered
});

// NOTE: /user, /ping, /import, /file, /login, /admin,
//       /hash-password, /payment, /fetch are ALL untested.
//
// This will drop line coverage well below the 80% threshold
// and cause the "Coverage threshold gate" step in the pipeline to fail.
