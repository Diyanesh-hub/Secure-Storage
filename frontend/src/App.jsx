import React, { useState, useEffect } from "react";
import { ethers } from "ethers";
import abi from "./contractJson/Upload.json";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import toast, { Toaster } from "react-hot-toast";
import ConnectButton from "./miniComponents/ConnectButton";
import SS from "./assets/images/SS.jpeg";
import ss from "./assets/images/ss.png";
import NavBar from "./miniComponents/NavBar";
import Footer from "./miniComponents/Footer"; // Import Footer component
import UploadCase from "./components/UploadCase";
import ShareAccess from "./components/ShareAccess";
import NotAllowed from "./components/NotAllowed";
import SecureDisplay from "./components/SecureDisplay";


function App() {
  const [state, setState] = useState({
    provider: null,
    signer: null,
    contract: null,
    account: null,
  });

  const [account, setAccount] = useState(
    localStorage.getItem("account") || "Not Connected"
  );
  const [modelOpen, setModelOpen] = useState(false);
  const [connected, setConnected] = useState(
    localStorage.getItem("connected") === "true" || false
  );

  useEffect(() => {
    if (connected) {
      connectToMetaMask();
    }
  }, []);

  const connectToMetaMask = async () => {
    const contractAddr = "xxxxxxxxxxx";
    const contractABI = abi.abi;

    console.log(contractABI, contractAddr);

    try {
      const { ethereum } = window;

      let signer = null;
      let provider;

      if (ethereum == null) {
        console.log("MetaMask not installed; using read-only defaults");
        provider = ethers.getDefaultProvider();
      } else {
        const accounts = await ethereum.request({
          method: "eth_requestAccounts",
        });
        const chosenAccount = accounts[0];
        setAccount(chosenAccount);
        localStorage.setItem("account", chosenAccount);
        provider = new ethers.BrowserProvider(ethereum);
        signer = await provider.getSigner();
      }

      window.ethereum.on("chainChanged", () => {
        window.location.reload();
      });

      window.ethereum.on("accountsChanged", (accounts) => {
        const chosenAccount = accounts[0];
        setAccount(chosenAccount);
        localStorage.setItem("account", chosenAccount);
        window.location.reload();
      });

      const contract = new ethers.Contract(contractAddr, contractABI, signer);
      setState({ provider, signer, contract, account });
      setConnected(true);
      localStorage.setItem("connected", true);
    } catch (err) {
      console.log(err);
    }
  };

  const disconnectFromMetaMask = () => {
    setConnected(false);
    setAccount("Not Connected");
    localStorage.setItem("connected", false);
    localStorage.removeItem("account");
    // Reset the state
    setState({
      provider: null,
      signer: null,
      contract: null,
      account: null,
    });
  };

  return (
    <div className="min-h-screen flex flex-col justify-between bg-primary">
      <Router>
        <NavBar />
        <Routes>
          <Route index />
          <Route
            path="/display"
            element={
              connected ? <SecureDisplay state={state} /> : <NotAllowed />
            }
          />
          <Route
            path="/upload"
            element={connected ? <UploadCase state={state} /> : <NotAllowed />}
          />
          <Route
            path="/share"
            element={connected ? <ShareAccess state={state} /> : <NotAllowed />}
          />
          
          
        </Routes>
        <Toaster />
      </Router>

      <div className="flex-grow flex flex-col justify-center items-center px-16 pb-16 mx-auto max-w-7xl">
        <div className="flex-grow flex flex-col justify-center items-center px-16 pb-16 mx-auto max-w-7xl">
          {!connected ? (
            <div className="flex flex-row gap-10 items-center justify-center h-full">
              <img
                src={SS}
                alt="per"
                border="0"
                className="mt-10 w-1/6 h-1/6"
              />
              <div>
                <h1 className="text-3xl text-textPrimary mt-20">
                  Connect to Blockchain
                </h1>
                <ConnectButton
                  onClick={connectToMetaMask}
                  disabled={connected}
                  text={connected ? "Connected" : "Connect with MetaMask"}
                />
              </div>
            </div>
          ) : (
            <div className="flex flex-row gap-10 items-center justify-center h-full">
              <img
                src={ss}
                alt="per"
                border="0"
                className="mt-10 w-1/4 h-1/4"
              />
              <div>
                <h1 className="text-3xl text-textPrimary mt-20">
                  Connected to: <br />
                  {account}{" "}
                </h1>
                <button
                  className="mt-5 bg-accent text-textPrimary px-4 py-2 rounded-md"
                  onClick={disconnectFromMetaMask}
                >
                  Disconnect
                </button>
              </div>
            </div>
          )}

          
        </div>
      </div>
      <Footer /> {/* Add Footer component */}
    </div>
  );
}

export default App;
