package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type singleCircuit struct {
	A        frontend.Variable
	B        frontend.Variable
	Expected frontend.Variable `gnark:",public"`
}

func (c *singleCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(api.Mul(c.A, c.B), c.Expected)
	return nil
}

type developerCircuit struct {
	A0       frontend.Variable
	A1       frontend.Variable
	A2       frontend.Variable
	A3       frontend.Variable
	B0       frontend.Variable
	B1       frontend.Variable
	B2       frontend.Variable
	B3       frontend.Variable
	Expected frontend.Variable `gnark:",public"`
}

func (c *developerCircuit) Define(api frontend.API) error {
	sum := api.Add(
		api.Mul(c.A0, c.B0),
		api.Mul(c.A1, c.B1),
		api.Mul(c.A2, c.B2),
		api.Mul(c.A3, c.B3),
	)
	api.AssertIsEqual(sum, c.Expected)
	return nil
}

type recursiveCircuit struct {
	Seed0    frontend.Variable
	Seed1    frontend.Variable
	Expected frontend.Variable `gnark:",public"`
}

func (c *recursiveCircuit) Define(api frontend.API) error {
	a := c.Seed0
	b := c.Seed1
	for i := 0; i < 8; i++ {
		next := api.Add(a, b)
		a = b
		b = next
	}
	api.AssertIsEqual(b, c.Expected)
	return nil
}

type summary struct {
	Scenario string `json:"scenario"`
	Verified bool   `json:"verified"`
}

func proveScenario(name string, outDir string) error {
	var circuit frontend.Circuit
	var assignment frontend.Circuit

	switch name {
	case "single_circuit_prove":
		circuit = &singleCircuit{}
		assignment = &singleCircuit{A: 3, B: 7, Expected: 21}
	case "developer_workload":
		circuit = &developerCircuit{}
		assignment = &developerCircuit{
			A0: 1, A1: 2, A2: 3, A3: 4,
			B0: 4, B1: 3, B2: 2, B3: 1,
			Expected: 20,
		}
	case "recursive_workflow":
		circuit = &recursiveCircuit{}
		assignment = &recursiveCircuit{Seed0: 1, Seed1: 1, Expected: 55}
	default:
		return fmt.Errorf("unknown scenario: %s", name)
	}

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		return err
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return err
	}
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return err
	}
	publicWitness, err := witness.Public()
	if err != nil {
		return err
	}
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		return err
	}
	verified := groth16.Verify(proof, vk, publicWitness) == nil
	if !verified {
		return fmt.Errorf("gnark verification failed for %s", name)
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	proofFile, err := os.Create(filepath.Join(outDir, "proof.bin"))
	if err != nil {
		return err
	}
	defer proofFile.Close()
	if _, err := proof.WriteTo(proofFile); err != nil {
		return err
	}
	vkFile, err := os.Create(filepath.Join(outDir, "vk.bin"))
	if err != nil {
		return err
	}
	defer vkFile.Close()
	if _, err := vk.WriteTo(vkFile); err != nil {
		return err
	}
	summaryFile, err := os.Create(filepath.Join(outDir, "summary.json"))
	if err != nil {
		return err
	}
	defer summaryFile.Close()
	return json.NewEncoder(summaryFile).Encode(summary{Scenario: name, Verified: verified})
}

func verifyScenario(name string, outDir string) error {
	summaryPath := filepath.Join(outDir, "summary.json")
	file, err := os.Open(summaryPath)
	if err != nil {
		return err
	}
	defer file.Close()
	var payload summary
	if err := json.NewDecoder(file).Decode(&payload); err != nil {
		return err
	}
	if payload.Scenario != name {
		return fmt.Errorf("summary scenario mismatch: expected %s, found %s", name, payload.Scenario)
	}
	if !payload.Verified {
		return fmt.Errorf("summary recorded verified=false for %s", name)
	}
	if _, err := os.Stat(filepath.Join(outDir, "proof.bin")); err != nil {
		return err
	}
	return nil
}

func main() {
	mode := flag.String("mode", "prove", "prove or verify")
	scenario := flag.String("scenario", "", "scenario id")
	outDir := flag.String("out-dir", "", "output directory")
	flag.Parse()

	if *scenario == "" || *outDir == "" {
		fmt.Fprintln(os.Stderr, "--scenario and --out-dir are required")
		os.Exit(2)
	}

	var err error
	if *mode == "prove" {
		err = proveScenario(*scenario, *outDir)
	} else {
		err = verifyScenario(*scenario, *outDir)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
