defmodule KZGTest do
  use ExUnit.Case

  doctest KZG

  @root "../../tests/"
  @blob_to_kzg_commitment_tests Path.wildcard(@root <> "blob_to_kzg_commitment/*/*/data.yaml")
  @compute_kzg_proof_tests Path.wildcard(@root <> "compute_kzg_proof/*/*/data.yaml")
  @compute_blob_kzg_proof_tests Path.wildcard(@root <> "compute_blob_kzg_proof/*/*/data.yaml")
  @verify_kzg_proof_tests Path.wildcard(@root <> "verify_kzg_proof/*/*/data.yaml")
  @verify_blob_kzg_proof_tests Path.wildcard(@root <> "verify_blob_kzg_proof/*/*/data.yaml")
  @verify_blob_kzg_proof_batch_tests Path.wildcard(
                                       @root <> "verify_blob_kzg_proof_batch/*/*/data.yaml"
                                     )
  @compute_cells_tests Path.wildcard(@root <> "compute_cells/*/*/data.yaml")
  @compute_cells_and_kzg_proofs_tests Path.wildcard(
                                        @root <> "compute_cells_and_kzg_proofs/*/*/data.yaml"
                                      )
  @recover_cells_and_kzg_proofs_tests Path.wildcard(
                                        @root <> "recover_cells_and_kzg_proofs/*/*/data.yaml"
                                      )
  @verify_cell_kzg_proof_batch_tests Path.wildcard(
                                       @root <> "verify_cell_kzg_proof_batch/*/*/data.yaml"
                                     )

  setup do
    {:ok, setup} = KZG.load_trusted_setup("../../src/trusted_setup.txt", 0)
    {:ok, setup: setup}
  end

  defp bytes_from_hex(hex) do
    hex
    |> String.replace("0x", "")
    |> Base.decode16!(case: :mixed)
  end

  test "blob_to_kzg_commitment/2 tests", %{setup: setup} do
    assert length(@blob_to_kzg_commitment_tests) > 0

    for file <- @blob_to_kzg_commitment_tests do
      {:ok, test_data} = YamlElixir.read_from_file(file)

      blob = bytes_from_hex(test_data["input"]["blob"])

      case KZG.blob_to_kzg_commitment(blob, setup) do
        {:error, _} ->
          assert test_data["output"] == nil

        {:ok, commitment} ->
          expected_commitment = bytes_from_hex(test_data["output"])

          assert commitment == expected_commitment,
                 "#{file}\nCommitment #{inspect(commitment)} does not match expected #{inspect(expected_commitment)}"
      end
    end
  end

  test "compute_kzg_proof/3 tests", %{setup: setup} do
    assert length(@compute_kzg_proof_tests) > 0

    for file <- @compute_kzg_proof_tests do
      {:ok, test_data} = YamlElixir.read_from_file(file)

      blob = bytes_from_hex(test_data["input"]["blob"])
      z = bytes_from_hex(test_data["input"]["z"])

      case KZG.compute_kzg_proof(blob, z, setup) do
        {:error, _} ->
          assert test_data["output"] == nil

        {:ok, proof, y} ->
          [proof_hex, y_hex] = test_data["output"]
          expected_proof = bytes_from_hex(proof_hex)
          expected_y = bytes_from_hex(y_hex)

          assert proof == expected_proof,
                 "#{file}\nProof #{inspect(proof)} does not match expected #{inspect(expected_proof)}"

          assert y == expected_y,
                 "#{file}\nY #{inspect(y)} does not match expected #{inspect(expected_y)}"
      end
    end
  end

  test "compute_blob_kzg_proof/3 tests", %{setup: setup} do
    assert length(@compute_blob_kzg_proof_tests) > 0

    for file <- @compute_blob_kzg_proof_tests do
      {:ok, test_data} = YamlElixir.read_from_file(file)

      blob = bytes_from_hex(test_data["input"]["blob"])
      commitment = bytes_from_hex(test_data["input"]["commitment"])

      case KZG.compute_blob_kzg_proof(blob, commitment, setup) do
        {:error, _} ->
          assert test_data["output"] == nil

        {:ok, proof} ->
          expected_proof = bytes_from_hex(test_data["output"])

          assert proof == expected_proof,
                 "#{file}\nProof #{inspect(proof)} does not match expected #{inspect(expected_proof)}"
      end
    end
  end

  test "verify_kzg_proof/5 tests", %{setup: setup} do
    assert length(@verify_kzg_proof_tests) > 0

    for file <- @verify_kzg_proof_tests do
      {:ok, test_data} = YamlElixir.read_from_file(file)

      commitment = bytes_from_hex(test_data["input"]["commitment"])
      z = bytes_from_hex(test_data["input"]["z"])
      y = bytes_from_hex(test_data["input"]["y"])
      proof = bytes_from_hex(test_data["input"]["proof"])

      case KZG.verify_kzg_proof(commitment, z, y, proof, setup) do
        {:error, _} ->
          assert test_data["output"] == nil

        {:ok, valid} ->
          assert valid == test_data["output"],
                 "#{file}\nResult #{inspect(valid)} does not match expected #{inspect(test_data["output"])}"
      end
    end
  end

  test "verify_blob_kzg_proof/4 tests", %{setup: setup} do
    assert length(@verify_blob_kzg_proof_tests) > 0

    for file <- @verify_blob_kzg_proof_tests do
      {:ok, test_data} = YamlElixir.read_from_file(file)

      blob = bytes_from_hex(test_data["input"]["blob"])
      commitment = bytes_from_hex(test_data["input"]["commitment"])
      proof = bytes_from_hex(test_data["input"]["proof"])

      case KZG.verify_blob_kzg_proof(blob, commitment, proof, setup) do
        {:error, _} ->
          assert test_data["output"] == nil

        {:ok, valid} ->
          assert valid == test_data["output"],
                 "#{file}\nResult #{inspect(valid)} does not match expected #{inspect(test_data["output"])}"
      end
    end
  end

  test "verify_blob_kzg_proof_batch/4 tests", %{setup: setup} do
    assert length(@verify_blob_kzg_proof_batch_tests) > 0

    for file <- @verify_blob_kzg_proof_batch_tests do
      {:ok, test_data} = YamlElixir.read_from_file(file)

      # Concatenate blobs, commitments, and proofs from the list of hex strings.
      blobs =
        test_data["input"]["blobs"]
        |> Enum.map(&bytes_from_hex/1)
        |> :erlang.iolist_to_binary()

      commitments =
        test_data["input"]["commitments"]
        |> Enum.map(&bytes_from_hex/1)
        |> :erlang.iolist_to_binary()

      proofs =
        test_data["input"]["proofs"]
        |> Enum.map(&bytes_from_hex/1)
        |> :erlang.iolist_to_binary()

      case KZG.verify_blob_kzg_proof_batch(blobs, commitments, proofs, setup) do
        {:error, _} ->
          assert test_data["output"] == nil

        {:ok, valid} ->
          assert valid == test_data["output"],
                 "#{file}\nResult #{inspect(valid)} does not match expected #{inspect(test_data["output"])}"
      end
    end
  end

  test "compute_cells/2 tests", %{setup: setup} do
    assert length(@compute_cells_tests) > 0

    for file <- @compute_cells_tests do
      {:ok, test_data} = YamlElixir.read_from_file(file)

      blob = bytes_from_hex(test_data["input"]["blob"])

      case KZG.compute_cells(blob, setup) do
        {:error, _} ->
          assert test_data["output"] == nil

        {:ok, cells} ->
          expected_cells = Enum.map(test_data["output"], &bytes_from_hex/1)

          assert cells == expected_cells,
                 "#{file}\nCells #{inspect(cells)} do not match expected #{inspect(expected_cells)}"
      end
    end
  end

  test "compute_cells_and_kzg_proofs/2 tests", %{setup: setup} do
    assert length(@compute_cells_and_kzg_proofs_tests) > 0

    for file <- @compute_cells_and_kzg_proofs_tests do
      {:ok, test_data} = YamlElixir.read_from_file(file)

      blob = bytes_from_hex(test_data["input"]["blob"])

      case KZG.compute_cells_and_kzg_proofs(blob, setup) do
        {:error, _} ->
          assert test_data["output"] == nil

        {:ok, cells, proofs} ->
          expected_cells =
            test_data["output"]
            |> List.first()
            |> Enum.map(&bytes_from_hex/1)

          expected_proofs =
            test_data["output"]
            |> List.last()
            |> Enum.map(&bytes_from_hex/1)

          assert cells == expected_cells,
                 "#{file}\nCells #{inspect(cells)} do not match expected #{inspect(expected_cells)}"

          assert proofs == expected_proofs,
                 "#{file}\nProofs #{inspect(proofs)} do not match expected #{inspect(expected_proofs)}"
      end
    end
  end

  test "recover_cells_and_kzg_proofs/3 tests", %{setup: setup} do
    assert length(@recover_cells_and_kzg_proofs_tests) > 0

    for file <- @recover_cells_and_kzg_proofs_tests do
      {:ok, test_data} = YamlElixir.read_from_file(file)

      cell_indices = test_data["input"]["cell_indices"]
      cells = Enum.map(test_data["input"]["cells"], &bytes_from_hex/1)

      case KZG.recover_cells_and_kzg_proofs(cell_indices, cells, setup) do
        {:error, _} ->
          assert test_data["output"] == nil

        {:ok, recovered_cells, recovered_proofs} ->
          expected_cells =
            test_data["output"]
            |> List.first()
            |> Enum.map(&bytes_from_hex/1)

          expected_proofs =
            test_data["output"]
            |> List.last()
            |> Enum.map(&bytes_from_hex/1)

          assert recovered_cells == expected_cells,
                 "#{file}\nRecovered cells #{inspect(recovered_cells)} do not match expected #{inspect(expected_cells)}"

          assert recovered_proofs == expected_proofs,
                 "#{file}\nRecovered proofs #{inspect(recovered_proofs)} do not match expected #{inspect(expected_proofs)}"
      end
    end
  end

  test "verify_cell_kzg_proof_batch/5 tests", %{setup: setup} do
    assert length(@verify_cell_kzg_proof_batch_tests) > 0

    for file <- @verify_cell_kzg_proof_batch_tests do
      {:ok, test_data} = YamlElixir.read_from_file(file)

      commitments =
        Enum.map(
          test_data["input"]["commitments"],
          &bytes_from_hex/1
        )

      cell_indices = test_data["input"]["cell_indices"]
      cells = Enum.map(test_data["input"]["cells"], &bytes_from_hex/1)
      proofs = Enum.map(test_data["input"]["proofs"], &bytes_from_hex/1)

      case KZG.verify_cell_kzg_proof_batch(commitments, cell_indices, cells, proofs, setup) do
        {:error, _} ->
          assert test_data["output"] == nil

        {:ok, valid} ->
          assert valid == test_data["output"],
                 "#{file}\nResult #{inspect(valid)} does not match expected #{inspect(test_data["output"])}"
      end
    end
  end
end
