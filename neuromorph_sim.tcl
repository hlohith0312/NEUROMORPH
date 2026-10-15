set ns [new Simulator]

$ns color 1 Red      ;# Phase 1: Vulnerable LLM traffic
$ns color 2 Green    ;# Phase 2: NeuroMorph protected traffic
$ns color 3 Orange   ;# Attacker sniffing/intercepting

set tracefile [open neuromorph.tr w]
$ns trace-all $tracefile

set namfile [open neuromorph.nam w]
$ns namtrace-all $namfile

# ORIGINAL 4-NODE TOPOLOGY
set client   [$ns node]   ;# Node 0: Client
set router   [$ns node]   ;# Node 1: Router
set server   [$ns node]   ;# Node 2: LLM Server
set attacker [$ns node]   ;# Node 3: Attacker

$ns duplex-link $client   $router   10Mb 10ms DropTail
$ns duplex-link $router   $server   10Mb 20ms DropTail
$ns duplex-link $router   $attacker 10Mb 5ms  DropTail

$ns duplex-link-op $client   $router   orient right
$ns duplex-link-op $router   $server   orient right
$ns duplex-link-op $router   $attacker orient down

$client   label "Client (You)"
$router   label "Router"
$server   label "LLM Server"
$attacker label "Attacker"

# -------------------------------------------------------
# PHASE 1: Vulnerable LLM Traffic (Red) - 0.5s to 4.0s
# Variable packet sizes = attacker sees LLM fingerprint
# -------------------------------------------------------
set udp1 [new Agent/UDP]
set null1 [new Agent/Null]
$ns attach-agent $client $udp1
$ns attach-agent $server $null1
$ns connect $udp1 $null1
$udp1 set fid_ 1
set cbr1 [new Application/Traffic/CBR]
$cbr1 attach-agent $udp1
$cbr1 set packetSize_ 64
$cbr1 set interval_ 0.050

set udp2 [new Agent/UDP]
set null2 [new Agent/Null]
$ns attach-agent $client $udp2
$ns attach-agent $server $null2
$ns connect $udp2 $null2
$udp2 set fid_ 1
set cbr2 [new Application/Traffic/CBR]
$cbr2 attach-agent $udp2
$cbr2 set packetSize_ 400
$cbr2 set interval_ 0.070

set udp3 [new Agent/UDP]
set null3 [new Agent/Null]
$ns attach-agent $client $udp3
$ns attach-agent $server $null3
$ns connect $udp3 $null3
$udp3 set fid_ 1
set cbr3 [new Application/Traffic/CBR]
$cbr3 attach-agent $udp3
$cbr3 set packetSize_ 1200
$cbr3 set interval_ 0.090

$ns at 0.5 "$cbr1 start"
$ns at 0.5 "$cbr2 start"
$ns at 0.5 "$cbr3 start"
$ns at 4.0 "$cbr1 stop"
$ns at 4.0 "$cbr2 stop"
$ns at 4.0 "$cbr3 stop"

# Attacker sniffing Phase 1 (Orange) - same interval as main traffic
set atk1 [new Agent/UDP]
set atk1_sink [new Agent/Null]
$ns attach-agent $router $atk1
$ns attach-agent $attacker $atk1_sink
$ns connect $atk1 $atk1_sink
$atk1 set fid_ 3
set cbr_atk1 [new Application/Traffic/CBR]
$cbr_atk1 attach-agent $atk1
$cbr_atk1 set packetSize_ 500
$cbr_atk1 set interval_ 0.055
$ns at 0.5 "$cbr_atk1 start"
$ns at 4.0 "$cbr_atk1 stop"

# -------------------------------------------------------
# PHASE 2: NeuroMorph Protected (Green) - 5.0s to 9.0s
# Constant 1400B = attacker sees only Netflix pattern
# -------------------------------------------------------
set udp_prot [new Agent/UDP]
set null_prot [new Agent/Null]
$ns attach-agent $client $udp_prot
$ns attach-agent $server $null_prot
$ns connect $udp_prot $null_prot
$udp_prot set fid_ 2
set cbr_prot [new Application/Traffic/CBR]
$cbr_prot attach-agent $udp_prot
$cbr_prot set packetSize_ 1400
$cbr_prot set interval_ 0.010

set udp_cover [new Agent/UDP]
set null_cover [new Agent/Null]
$ns attach-agent $client $udp_cover
$ns attach-agent $server $null_cover
$ns connect $udp_cover $null_cover
$udp_cover set fid_ 2
set cbr_cover [new Application/Traffic/CBR]
$cbr_cover attach-agent $udp_cover
$cbr_cover set packetSize_ 1400
$cbr_cover set interval_ 0.020

$ns at 5.0 "$cbr_prot  start"
$ns at 5.0 "$cbr_cover start"
$ns at 9.0 "$cbr_prot  stop"
$ns at 9.0 "$cbr_cover stop"

# Attacker sniffing Phase 2 (Orange) - still watching but useless
set atk2 [new Agent/UDP]
set atk2_sink [new Agent/Null]
$ns attach-agent $router $atk2
$ns attach-agent $attacker $atk2_sink
$ns connect $atk2 $atk2_sink
$atk2 set fid_ 3
set cbr_atk2 [new Application/Traffic/CBR]
$cbr_atk2 attach-agent $atk2
$cbr_atk2 set packetSize_ 500
$cbr_atk2 set interval_ 0.015
$ns at 5.0 "$cbr_atk2 start"
$ns at 9.0 "$cbr_atk2 stop"

proc finish {} {
    global ns tracefile namfile
    $ns flush-trace
    close $tracefile
    close $namfile
    puts ""
    puts "=============================================="
    puts " NeuroMorph NS2 Simulation Complete!"
    puts "=============================================="
    puts " Files generated:"
    puts "   neuromorph.tr  -- trace data"
    puts "   neuromorph.nam -- NAM animation"
    puts " To view: nam neuromorph.nam"
    puts " To analyse: bash analyze.sh"
    puts "=============================================="
    exit 0
}

$ns at 10.0 "finish"
$ns run
