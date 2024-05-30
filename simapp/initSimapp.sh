# change chis address whenever the circuit is compiled
ADDR=cosmos1vu67ks20vuqr58s0vejgfyyqp3dlch8jfznyd4
VAL=cosmosvaloper1m4hdyzy4ndgezefmvx48gk5jxzlgy8q6fh7wtv

rm -rf ~/.simapp
simd init abed --chain-id my-zk-test-chain
simd keys add me --keyring-backend test
simd genesis add-genesis-account me 100000000000stake --keyring-backend test
simd genesis add-genesis-account $ADDR 100000000000000stake  --keyring-backend test
simd genesis gentx me 100000000stake --chain-id my-zk-test-chain --keyring-backend test
simd genesis collect-gentxs 