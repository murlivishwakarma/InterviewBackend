// import { verifyToken } from "../../../../config/jwt.config.js";
// import { Candidate } from "../../../../models/candidate.model.js";
// import { Interviewer } from "../../../../models/interviewer.model.js";

// export const verifyJWT = async (req, res, next) => {
//   const { accessToken } = req.cookies;

//   if (!accessToken) {
//     console.error("Access token is missing in cookies");
//     return res.status(401).json({ message: "Invalid access token" });
//   }

//   let decodedToken;
//   try {
//     decodedToken = await verifyToken(accessToken);
//     // console.log("Token successfully decoded:", decodedToken);
//   } catch (error) {
//     console.error("Error decoding token:", error.message);
//     return res.status(401).json({ message: "Invalid or expired token" });
//   }

//   let user;
//   try {
//     user = await Interviewer.findById(decodedToken.payload).select(
//       "-passwordHash -accessToken -refreshToken"
//     );

//     if (user) {
//       // console.log("Interviewer found:", user._id);
//       user = { ...user.toObject(), type: "interviewer" }; // Explicitly add type
//     } else {
//       // console.log("No interviewer found, checking for candidate...");
//       user = await Candidate.findById(decodedToken.payload).select(
//         "-passwordHash -accessToken -refreshToken"
//       );

//       if (user) {
//         // console.log("Candidate found:", user._id);
//         user = { ...user.toObject(), type: "candidate" }; // Explicitly add type
//       }
//     }
//   } catch (error) {
//     console.error("Error querying database:", error.message);
//     return res.status(500).json({ message: "Internal server error" });
//   }

//   if (!user) {
//     console.error("No user found for the provided token payload");
//     return res.status(401).json({ message: "No user found" });
//   }

//   // console.log("User successfully authenticated:", user._id, "Type:", user.type);
//   req.user = user;
//   next();
// };


import jwt from "jsonwebtoken";
import { verifyToken } from "../../../../config/jwt.config.js";
import { Candidate } from "../../../../models/candidate.model.js";
import { Interviewer } from "../../../../models/interviewer.model.js";
import {
  generateAccessToken,
} from "../../../../config/jwt.config.js";

export const verifyJWT = async (req, res, next) => {
  const { accessToken, refreshToken } = req.cookies;

  if (!accessToken && !refreshToken) {
    return res.status(401).json({ message: "Authentication required" });
  }

  let decoded;

  // ---------------------------
  // 1️⃣ TRY ACCESS TOKEN FIRST
  // ---------------------------
  try {
    decoded = jwt.verify(accessToken, process.env.JWT_SECRET);
  } catch (err) {
    // Expired access token → try refresh
    if (err.name === "TokenExpiredError") {
      console.log("Access token expired → checking refresh token");

      if (!refreshToken) {
        return res.status(401).json({ message: "Session expired. Please login again." });
      }

      try {
        // ---------------------------
        // 2️⃣ VERIFY REFRESH TOKEN
        // ---------------------------
        const refreshDecoded = jwt.verify(refreshToken, process.env.JWT_SECRET);

        // ---------------------------
        // 3️⃣ GENERATE NEW ACCESS TOKEN
        // ---------------------------
        const newAccessToken = await generateAccessToken(refreshDecoded.payload);

        // Send new access token as cookie
        res.cookie("accessToken", newAccessToken, {
          httpOnly: true,
          secure: true,
          sameSite: "none",
        });

        // Replace decoded object for further logic
        decoded = refreshDecoded;

        console.log("New access token issued.");

      } catch (refreshErr) {
        console.error("Refresh token invalid:", refreshErr.message);
        return res.status(401).json({ message: "Session expired. Please login again." });
      }

    } else {
      // Other token errors
      return res.status(401).json({ message: "Invalid token" });
    }
  }

  // ---------------------------
  // 4️⃣ FETCH USER FROM DB
  // ---------------------------
  let user =
    (await Interviewer.findById(decoded.payload).select(
      "-passwordHash -accessToken -refreshToken"
    )) ||
    (await Candidate.findById(decoded.payload).select(
      "-passwordHash -accessToken -refreshToken"
    ));

  if (!user) {
    return res.status(401).json({ message: "No user found" });
  }

  req.user = {
    ...user.toObject(),
    type: user.role || user.type || (user.email.includes("interviewer") ? "interviewer" : "candidate"),
  };

  next();
};

