defmodule KZG do
  @moduledoc """
  Elixir bindings for the CKZG (C-KZG) library, providing KZG polynomial commitment scheme functionality.

  This module exposes functions to:
    - load a trusted setup
    - convert a blob to a commitment
    - compute and verify proofs
    - compute cells and proofs
    - recover missing cells and proofs

  ## Examples

      # Load trusted setup
      {:ok, settings} = KZG.load_trusted_setup("path/to/setup.txt", 0)

      # Convert blob to commitment
      blob = <<0::size(4096 * 32 * 8)>>
      {:ok, commitment} = KZG.blob_to_kzg_commitment(blob, settings)

      # Compute KZG proof
      z = <<1::size(32 * 8)>>
      {:ok, proof, y} = KZG.compute_kzg_proof(blob, z, settings)
  """

  @on_load :on_load
  def on_load do
    path = :filename.join([:code.priv_dir(:ckzg), "ckzg_nif"])
    :erlang.load_nif(path, 0)
  end

  @typedoc """
  Reference to the trusted settings.
  """
  @type settings :: reference()

  @typedoc """
  Binary blob data (4096 * 32 bytes).
  """
  @type blob :: <<_::unquote(4096 * 32), _::_*8>>

  @typedoc """
  KZG commitment (48 bytes).
  """
  @type commitment :: <<_::48, _::_*8>>

  @typedoc """
  KZG proof (48 bytes).
  """
  @type proof :: <<_::48, _::_*8>>

  @typedoc """
  Field element (32 bytes).
  """
  @type field_element :: <<_::32, _::_*8>>

  @doc """
  Loads the trusted setup from a file path.

  ## Parameters

    - `path` is a string path to the trusted setup file.
    - `precompute` is an integer flag (e.g. 0 for no precompute).

  ## Returns

    - `{:ok, settings}` on success.
    - `{:error, reason}` on failure.
  """
  @spec load_trusted_setup(String.t(), integer()) :: {:ok, settings} | {:error, atom()}
  def load_trusted_setup(_path, _precompute) do
    :erlang.nif_error(:not_loaded)
  end

  @doc """
  Converts a blob to a KZG commitment.

  ## Parameters

    - `blob` is the binary blob.
    - `settings` is the trusted setup reference.

  ## Returns

    - `{:ok, commitment}` on success.
    - `{:error, reason}` on failure.
  """
  @spec blob_to_kzg_commitment(blob, settings) :: {:ok, commitment} | {:error, atom()}
  def blob_to_kzg_commitment(_blob, _settings) do
    :erlang.nif_error(:not_loaded)
  end

  @doc """
  Computes a KZG proof from a blob given a field element `z`.

  ## Parameters

    - `blob` is the binary blob.
    - `z` is a field element (32-byte binary).
    - `settings` is the trusted settings reference.

  ## Returns

    - `{:ok, proof, y}` on success, where `proof` is the computed proof and `y` is the evaluation.
    - `{:error, reason}` on failure.
  """
  @spec compute_kzg_proof(blob, field_element, settings) ::
          {:ok, {proof, field_element}} | {:error, atom()}
  def compute_kzg_proof(_blob, _z, _settings) do
    :erlang.nif_error(:not_loaded)
  end

  @doc """
  Computes a KZG proof from a blob using a commitment instead of a field element.

  ## Parameters

    - `blob` is the binary blob.
    - `commitment` is a KZG commitment binary.
    - `settings` is the trusted settings reference.

  ## Returns

    - `{:ok, proof}` on success, where `proof` is a 48 byte KZG proof.
    - `{:error, reason}` on failure.
  """
  @spec compute_blob_kzg_proof(blob, commitment, settings) :: {:ok, proof} | {:error, atom()}
  def compute_blob_kzg_proof(_blob, _commitment, _settings) do
    :erlang.nif_error(:not_loaded)
  end

  @doc """
  Verifies a KZG proof given a commitment, field elements `z` and `y`, and a proof.

  ## Parameters

    - `commitment` is the KZG commitment binary.
    - `z` is a 32-byte field element.
    - `y` is a 32-byte field element.
    - `proof` is the KZG proof binary.
    - `settings` is the trusted settings reference.

  ## Returns

    - `{:ok, true}` if verification is successful.
    - `{:ok, false}` if verification fails.
    - `{:error, reason}` on error.
  """
  @spec verify_kzg_proof(commitment, field_element, field_element, proof, settings) ::
          {:ok, boolean} | {:error, atom()}
  def verify_kzg_proof(_commitment, _z, _y, _proof, _settings) do
    :erlang.nif_error(:not_loaded)
  end

  @doc """
  Verifies a blob against a commitment and its KZG proof.

  ## Parameters

    - `blob` is the binary blob.
    - `commitment` is the KZG commitment binary.
    - `proof` is the KZG proof binary.
    - `settings` is the trusted settings reference.

  ## Returns

    - `{:ok, true}` if verification is successful.
    - `{:ok, false}` if verification fails.
    - `{:error, reason}` on error.
  """
  @spec verify_blob_kzg_proof(blob, commitment, proof, settings) ::
          {:ok, boolean} | {:error, atom()}
  def verify_blob_kzg_proof(_blob, _commitment, _proof, _settings) do
    :erlang.nif_error(:not_loaded)
  end

  @doc """
  Verifies a batch of blob proofs with their corresponding commitments.

  ## Parameters

    - `blobs` is a binary containing concatenated blobs.
    - `commitments` is a binary containing concatenated commitments.
    - `proofs` is a binary containing concatenated proofs.
    - `settings` is the trusted settings reference.

  ## Returns

    - `{:ok, true}` if batch verification is successful.
    - `{:ok, false}` if batch verification fails.
    - `{:error, reason}` on error.
  """
  @spec verify_blob_kzg_proof_batch(binary, binary, binary, settings) ::
          {:ok, boolean} | {:error, atom()}
  def verify_blob_kzg_proof_batch(_blobs, _commitments, _proofs, _settings) do
    :erlang.nif_error(:not_loaded)
  end

  @doc """
  Computes cells from a blob.

  ## Parameters

    - `blob` is the binary blob.
    - `settings` is the trusted settings reference.

  ## Returns

    - `{:ok, cells_binary}` on success, where `cells_binary` is a binary containing all cells.
    - `{:error, reason}` on error.
  """
  @spec compute_cells(blob, settings) :: {:ok, binary} | {:error, atom()}
  def compute_cells(_blob, _settings) do
    :erlang.nif_error(:not_loaded)
  end

  @doc """
  Computes cells and the corresponding KZG proofs from a blob.

  ## Parameters

    - `blob` is the binary blob.
    - `settings` is the trusted settings reference.

  ## Returns

    - `{:ok, cells_binary, proofs_binary}` on success, where `cells_binary` is a binary containing all cells,
        and `proofs_binary` is a binary containing all proofs.
    - `{:error, reason}` on error.
  """
  @spec compute_cells_and_kzg_proofs(blob, settings) :: {:ok, binary, binary} | {:error, atom()}
  def compute_cells_and_kzg_proofs(_blob, _settings) do
    :erlang.nif_error(:not_loaded)
  end

  @doc """
  Recovers missing cells and their proofs given cell indices and available cells.

  ## Parameters

    - `cell_indices` is a list of non-negative integers (cell indices).
    - `cells` is a list of binary cells.
    - `settings` is the trusted settings reference.

  ## Returns

    - `{:ok, cells_list, proofs_list}` on success, where `cells_list` and `proofs_list` are lists of binary cells and proofs respectively.
    - `{:error, reason}` on error.
  """
  @spec recover_cells_and_kzg_proofs([non_neg_integer()], [binary], settings) ::
          {:ok, [binary()], [binary()]} | {:error, atom()}
  def recover_cells_and_kzg_proofs(_cell_indices, _cells, _settings) do
    :erlang.nif_error(:not_loaded)
  end

  @doc """
  Verifies a batch of cell proofs with their corresponding commitments.

  ## Parameters

    - `commitments` is a binary containing concatenated commitments.
    - `cell_indices` is a list of non-negative integers (cell indices).
    - `cells` is a list of binary cells.
    - `proofs` is a binary containing concatenated proofs.
    - `settings` is the trusted settings reference.

  ## Returns

    - `{:ok, true}` if batch verification is successful.
    - `{:ok, false}` if batch verification fails.
    - `{:error, reason}` on error.
  """
  @spec verify_cell_kzg_proof_batch(binary, [non_neg_integer()], [binary], binary, settings) ::
          {:ok, boolean} | {:error, atom()}
  def verify_cell_kzg_proof_batch(_commitments, _cell_indices, _cells, _proofs, _settings) do
    :erlang.nif_error(:not_loaded)
  end
end
