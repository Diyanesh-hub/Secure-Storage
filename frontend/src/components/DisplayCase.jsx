import React, { useState } from "react";
import CryptoJS from "crypto-js";
import MapDisplay from "../miniComponents/MapDisplay";
import ShareAccess from "./ShareAccess";
import './global.js';

const userPrivateKey = 'xxxxxxxxxxxxxxxx';

const DisplayCase = ({ state }) => {
    const { account, contract, signer } = state;
    const [caseData, setCaseData] = useState([]);
    const [selectedCase, setSelectedCase] = useState(null);
    const [showShareAccess, setShowShareAccess] = useState(false); 
    const [selectedCaseID, setSelectedCaseID] = useState(null);

    const downloadFile = (name, data) => {
        const byteCharacters = atob(data);
        const byteNumbers = new Array(byteCharacters.length);
        for (let i = 0; i < byteCharacters.length; i++) {
            byteNumbers[i] = byteCharacters.charCodeAt(i);
        }
        const byteArray = new Uint8Array(byteNumbers);
        const blob = new Blob([byteArray], { type: 'application/octet-stream' });
    
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = name;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    };

    const handleViewDetails = async (caseID) => {
        const selected = caseData.find((item) => item.caseID === caseID);
        console.log("Decrypted CID:", selected.decryptedCID);

        if (selected) {
            try {
                const response = await fetch(`https://gateway.pinata.cloud/ipfs/${selected.decryptedCID}`);
                if (response.ok) {
                    const responseData = await response.json();
                    setSelectedCase({ ...selected, files: responseData.filesData.files });
                } else {
                    console.log(`Error fetching data for CID: ${selected.decryptedCID}`);
                }
            } catch (error) {
                console.error(`Error fetching data for CID: ${selected.decryptedCID}`, error);
            }
        }
    };

    const getCaseData = async () => {
        const otherAddress = document.querySelector("#acc").value;
        console.log("otherAddress: " + otherAddress);
        console.log(await contract.displayCases(account));
        try {
            const dataArray = otherAddress
                ? await contract.displayCases(otherAddress)
                : await contract.displayCases(account);

            const decryptedDataArray = [];
            for (let i = 0; i < dataArray.length; i++) {
                const caseID = dataArray[i];
                const encryptedCID = await contract.getCaseData(caseID);
                const decryptedCID = CryptoJS.AES.decrypt(encryptedCID.toString(), userPrivateKey).toString(CryptoJS.enc.Utf8);
                decryptedDataArray.push({ caseID, decryptedCID });
            }

            console.log(decryptedDataArray);
            setCaseData(decryptedDataArray);
            const logData = {
                address: account,
                caseName: 'N/A',
                event: 'View Accessible Files',
                timestamp: new Date().toISOString(),
                result: 'success'
            };
            await sendLogToServer(logData);
        } catch (e) {
            alert("You don't have access or an error occurred");
            console.error(e);
            const logData = {
                address: account,
                caseName: 'N/A',
                event: 'View Case',
                timestamp: new Date().toISOString(),
                result: 'error' + e.message
            };
            await sendLogToServer(logData);
        }
    };

    const handleShareAccess = (caseID) => {
        setSelectedCaseID(caseID);
        setShowShareAccess(true);
    };

    const sendLogToServer = async (logData) => {
        try {
            console.log('Log Data:', logData);
            const response = await fetch('http://192.168.0.110:5000/logs', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(logData)
            });
            const data = await response.json();
            console.log('Log sent successfully:', data);
        } catch (error) {
            console.error('Error sending log:', error);
        }
    };

    return (
        <div className="w-full h-full p-10 justify-center items-center mx-auto bg-[#030014] max-w-7xl overflow-y-hidden overflow-x-hidden">
            <div className="p-5 flex gap-2 justify-center items-center">
                <input type="text" id="acc" placeholder="Enter Address" className="w-[50%] rounded-md h-10 placeholder: px-5 py-1" />
                <button className="w-[15%] h-10 rounded-md bg-blue-400 text-black" onClick={getCaseData}>
                    Get Data
                </button>
            </div>
            <div className="grid grid-cols-2 gap-10">
                {caseData.map((item, index) => (
                    <div key={index} className=" bg-slate-700 p-4 rounded-md">
                        <MapDisplay title="caseID" text={item.caseID} />
                        <div className="mt-2 flex gap-4">
                        <button
                            className="mt-2 text-blue-500 hover:text-blue-700"
                            onClick={() => handleViewDetails(item.caseID)}
                        >
                            View Details
                        </button>
                        <button
                            className="mt-2 text-blue-500 hover:text-blue-700"
                            onClick={() => handleShareAccess(item.caseID)}
                        >
                            Manage Access
                        </button>
                        </div>
                    </div>
                ))}
            </div>
            {showShareAccess && (
                <ShareAccess
                    state={state}
                    selectedCaseID={selectedCaseID}
                    onClose={() => setShowShareAccess(false)}
                />
            )}
            {selectedCase && (
                <div className="mt-10 w-full bg-slate-700 p-4 rounded-md">
                    <MapDisplay title="caseID" text={selectedCase.caseID} />
                    <div className="mt-2">
                        {selectedCase.files.map((file, idx) => (
                            <div key={idx} className="flex items-center">
                                <span className="mr-2 text-yellow-500">{file.name}</span>
                                <button
                                    className="text-blue-500 hover:text-blue-700"
                                    onClick={() => downloadFile(file.name, file.data)}
                                >
                                    Download
                                </button>
                            </div>
                        ))}
                        <button
                            className="mt-2 text-blue-500 hover:text-blue-700"
                            onClick={() => handleShareAccess(selectedCase.caseID)}
                        >
                            Manage Access
                        </button>
                    </div>
                </div>
            )}
        </div>
    );
};

export default DisplayCase;
