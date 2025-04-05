 import React, { useState } from "react";
 import CryptoJS from "crypto-js";
 import toast from "react-hot-toast";
 import { IoIosCheckmarkCircle, IoIosCheckmarkCircleOutline } from "react-icons/io";
 
 const UploadCase = ({ state }) => {
   const { account, contract } = state;
 
   const [caseName, setCaseName] = useState("");
   const [file, setFile] = useState(null);
   const [uniqueCaseID, setUniqueCaseID] = useState("");
   const [loading, setLoading] = useState(false);
 
   const handleFileInputChange = (event) => {
     const selectedFile = event.target.files[0];
     if (selectedFile) {
       const reader = new FileReader();
       reader.onload = () => {
         const fileData = reader.result.split(",")[1];
         setFile({ name: selectedFile.name, data: fileData, raw: selectedFile }); // include raw for scanning
       };
       reader.readAsDataURL(selectedFile);
     }
   };
 
   // Malware scan API call
   const checkForMalware = async (rawFile) => {
     const formData = new FormData();
     formData.append("image", rawFile);
 
     try {
       const response = await fetch("http://localhost:5000/check", {
         method: "POST",
         body: formData,
       });
 
       const data = await response.json();
       console.log("🧪 Malware scan response:", data); 
 
       // Fallback in case status is undefined
       return data?.status || "error";
     } catch (error) {
       console.error("Malware check error:", error);
       return "error";
     }
   };
 
   const handleUpload = async (event) => {
     event.preventDefault();
 
     if (!account || !caseName || !file) {
       toast.error("Please fill in all the details and upload a file.");
       return;
     }
 
     //Step 1: Malware Scan
     const status = await checkForMalware(file.raw);
     if (status === "malicious") {
       toast.error("Malicious file detected! Upload blocked.");
       return;
     } 
    
      else if (status === "error") {
       toast.error("Unable to scan file. Try again.");
       return;
     }
     
 
     // Step 2: Proceed with Upload
     setLoading(true);
     const hash = CryptoJS.SHA256(caseName);
     const hashedCaseID = hash.toString(CryptoJS.enc.Hex);
     setUniqueCaseID(hashedCaseID);
 
     const fileData = {
       file,
       uniqueCaseID: caseName + hashedCaseID,
     };
 
     const userPrivateKey = "xxxxxxxxxx";
     const IPFS_Key = "xxxxxxxxxxx";

     const options = {
       method: "POST",
       headers: {
         Authorization: "Bearer " + IPFS_Key,
         "Content-Type": "application/json",
       },
       body: JSON.stringify({
         pinataContent: fileData,
         pinataMetadata: { name: caseName + ".json" },
         pinataOptions: { cidVersion: 1 },
       }),
     };
 
     try {
       const response = await fetch("https://api.pinata.cloud/pinning/pinJSONToIPFS", options);
       const data = await response.json();
       if (data && data.IpfsHash) {
         const encryptedCID = CryptoJS.AES.encrypt(data.IpfsHash, userPrivateKey).toString();
         const transaction = await contract.addCase(caseName, encryptedCID);
         const receipt = await transaction.wait();
 
         if (receipt.status === 1) {
           toast.success("Transaction Successful");
         } else {
           toast.error("Transaction failed");
         }
       } else {
         toast.error("Invalid CID received from IPFS");
       }
     } catch (err) {
       toast.error("Error uploading file");
       console.error(err);
     } finally {
       setLoading(false);
     }
   };
 
   return (
     <div className="w-full h-screen py-5 justify-center items-center mx-auto bg-[#030014] max-w-7xl overflow-x-hidden overflow-y-hidden">
       <form className="w-full mx-auto px-5 py-3 flex gap-10 justify-between">
         <div className="w-1/2 flex flex-col">
           <div className="mb-5">
             <label htmlFor="account" className="block mb-2 text-sm font-medium text-white">Connected Account</label>
             <input type="text" id="account" className="shadow-sm border text-sm rounded-lg block w-full p-2.5 bg-gray-700 border-gray-600 placeholder-gray-400 text-white" value={account || ""} readOnly />
           </div>
           <div className="mb-5">
             <label htmlFor="caseName" className="block mb-2 text-sm font-medium text-white">Unique File Name</label>
             <input type="text" id="caseName" className="shadow-sm border text-sm rounded-lg block w-full p-2.5 bg-gray-700 border-gray-600 placeholder-gray-400 text-white" value={caseName} onChange={(e) => setCaseName(e.target.value)} required />
           </div>
           <div className="mb-5 flex flex-row gap-x-10 items-center justify-between">
             <div className="flex gap-5 items-center">
               {file ? <IoIosCheckmarkCircle className="text-green-500 w-6 h-6" /> : <IoIosCheckmarkCircleOutline className="text-gray-400 w-6 h-6" />}
               <label htmlFor="file" className="block text-sm font-medium text-white">Upload File</label>
               {file && <span className="text-sm text-gray-300">{file.name}</span>}
             </div>
             <input type="file" id="file" className="hidden" onChange={handleFileInputChange} accept="image/*" />
             <label htmlFor="file" className="cursor-pointer bg-blue-500 text-white py-2 px-4 rounded-lg">Choose File</label>
           </div>
           <div className="flex flex-col items-start gap-2">
             <button type="submit" onClick={handleUpload} disabled={loading} className="w-2/3 text-white bg-blue-500 hover:bg-blue-600 font-medium rounded-lg text-sm px-5 py-2.5">Upload File</button>
             <button type="reset" className="w-1/3 text-white bg-red-500 hover:bg-red-600 font-medium rounded-lg text-sm px-5 py-2.5" onClick={() => { setCaseName(""); setFile(null); setUniqueCaseID(""); }}>Reset</button>
             {loading && <div className="flex items-center justify-center gap-2 text-blue-300"><IoIosCheckmarkCircleOutline size={20} />Uploading file, please wait...</div>}
             {uniqueCaseID && <div className="text-green-400 mt-4">Case ID generated: {uniqueCaseID}</div>}
           </div>
         </div>
       </form>
     </div>
   );
 };
 
 export default UploadCase;
 