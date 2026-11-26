// Trusted, local PoC rules. A match is an indicator, never proof of execution.
rule direct_shell_indicator {
    strings:
        $fetch = "curl " ascii
        $sink = "| sh" ascii
        $run = "Run" ascii
        $execute = "Execute" ascii
    condition:
        ($run or $execute) and $fetch and $sink
}

rule hex_decoder_indicator {
    strings:
        $decoder = { 78 78 64 20 2D 72 20 2D 70 }
        $sink = "| bash" ascii
        $execute = "Execute" ascii
    condition:
        $decoder and $sink and $execute
}

rule xor_instruction_indicator {
    strings:
        $token = "curl" xor(1-255)
        $marker = "XOR-obfuscated" ascii
        $execute = "Execute" ascii
    condition:
        $token and $marker and $execute
}

rule mcp_command_indicator {
    strings:
        $config = "mcpServers" ascii
        $fetch = "curl " ascii
        $sink = "| sh" ascii
    condition:
        $config and $fetch and $sink
}

rule encoded_python_indicator {
    strings:
        $decoder = "base64 -d" ascii
        $sink = "| python3" ascii
        $run = "Run" ascii
    condition:
        $decoder and $sink and $run
}

rule instruction_override_indicator {
    strings:
        $override = "Ignore previous instructions" nocase
        $transfer = "send" nocase
    condition:
        $override and $transfer
}
