"""
BFS/DFS call graph traversal query system for InfraPystatic analysis DB

supported queries:
    1. is_caller(A, B)      -- Is A a direct or indirect caller of B? Returns True/False + path
    2. shortest_path(A, B)  -- What is the shortest call chain from A to B?
    3. all_callees(A)       -- What functions can A reach (directly or transitively)?
    4. all_callers(B)       -- What functions eventually call B?

Usage:
"""

import sqlite3
import collections
import argparse

# load graph from DB
def load_call_graph(db_path: str) -> tuple:
    conn = sqlite3.connect(db_path)

    rows = conn.execute("""
        SELECT caller, callee
        FROM static_analysis
        WHERE analysis_type = 'call_graph'
    """).fetchall()
    conn.close()

    forward = collections.defaultdict(list)
    reverse = collections.defaultdict(list)
    for caller, callee in rows:
        forward[caller].append(callee)
        reverse[callee].append(caller)

    return dict(forward), dict(reverse)

#
# QUERY FUNCTIONS
#

def is_caller(forward: dict, func_a: str, func_b:str) -> tuple:
    """
    Is func_a a direct or indirect caller of func_b?
    Returns (bool, path_list) where path_list is the call chain found
    """
    if func_a not in forward:
        return False, []
    
    #BFS with parent tracking
    visited = {func_a}
    queue = collections.deque([[func_a]])

    while queue:
        path = queue.popleft()
        current = path[-1]

        for callee in forward.get(current, []):
            if callee == func_b:
                return True, path + [callee]
            if callee not in visited:
                visited.add(callee)
                queue.append(path + [callee])
    return False, []

def shortest_path(forward: dict, func_a: str, func_b: str)-> list:
    """
    Find shortest call chain from func_a to func_b
    returns the path as a list or empty list if no path exists
    """
    found, path = is_caller(forward, func_a, func_b)
    return path if found else []

def all_callees(forward: dict, func_a: str)-> list:
    """
    Return all functions reachable (directly or transitively) from func_a
    """
    if func_a not in forward:
        return []
    
    visited = set()
    queue = collections.deque([func_a])

    while queue:
        current = queue.popleft()
        for callee in forward.get(current, []):
            if callee not in visited:
                visited.add(callee)
                queue.append(callee)

    return sorted(visited)

def all_callers(reverse: dict, func_b: str)-> list:
    """
    BFS on reverse graph: return all functions that eventually call func_b
    """
    if func_b not in reverse:
        return []
    
    visited = set()
    queue = collections.deque([func_b])

    while queue:
        current = queue.popleft()
        for caller in reverse.get(current, []):
            if caller not in visited:
                visited.add(caller)
                queue.append(caller)

    return sorted(visited)

def direct_callees(forward: dict, func_a: str)-> list:
    """Return functions that func_a calls directly (one hop)"""
    return sorted(forward.get(func_a, []))

def direct_callers(reverse: dict, func_b: str)-> list:
    """Return functions that call func_b directly (one hop)"""
    return sorted(reverse.get(func_b, []))

#
# Printing helper functions
#

def print_path(path: list):
    if not path:
        print(" No path found.")
    else:
        print(" " + "-> ".join(path))

def print_list(label: str, items: list):
    if not items:
        print(f" No {label} found.")
    else:
        for item in items:
            print(f" * {item}")

#
#   Interactive Shell
#

def interactive_shell(db_path: str):
    """
    Simple interactive prompt shell
    Can run multiple queuries without restarting the script
    """

    forward, reverse = load_call_graph(db_path)
    all_functions = sorted(set(list(forward.keys()) + list(reverse.keys())))

    print("\n========================================")
    print("  InfraPy Call Graph Query System")
    print("========================================")
    print(f"  Loaded {sum(len(v) for v in forward.values())} call edges")
    print(f"  Functions in graph: {len(all_functions)}")
    print("\nCommands:")
    print("  is_caller <A> <B>    -- Is A a caller of B?")
    print("  path <A> <B>         -- Shortest call path from A to B")
    print("  callees <A>          -- All functions A can reach")
    print("  callers <B>          -- All functions that call B")
    print("  direct <A>           -- Direct calls made by A")
    print("  who_calls <B>        -- Direct callers of B")
    print("  list                 -- List all functions in graph")
    print("  quit                 -- Exit")
    print("========================================\n")


    while True:
        try:
            raw = input("query> ").strip()
        except(EOFError, KeyboardInterrupt):
            print("\nExiting")
            break

        if not raw:
            continue
            
        parts = raw.split()
        cmd = parts[0].lower()

        if cmd == "quuit":
            break

        elif cmd == "list":
            print(f"\n All {len(all_functions)} functions:")
            print_list("functions", all_functions)
        elif cmd == "is_caller" and len(parts) == 3:
            a, b = parts[1], parts[2]
            found, path = is_caller(forward, a, b)
            if found:
                print(f"\n Yes! {a} is a caller of {b}")
                print(f" Path:")
                print_path(path)
            else:
                print(f"\n No! {a} cannot reach {b}")
        elif cmd == "path" and len(parts) == 3:
            a, b = parts[1], parts[2]
            path = shortest_path(forward, a, b)
            print(f"\n Shortest path from {a} to {b}:")
            print_path(path)

        elif cmd == "callees" and len(parts) == 2:
            a = parts[1]
            results = all_callees(forward, a)
            print(f"\n All functions reachable from {a} ({len(results)} total):")
            print_list("callees", results)
        elif cmd == "callers" and len(parts) == 2:
            b = parts[1]
            results = all_callers(reverse, b)
            print(f"\n All functions that call {b} ({len(results)} total):")
            print_list("callers", results)
        elif cmd == "direct" and len(parts) == 2:
            a = parts[1]
            results = direct_callees(forward, a)
            print(f"\n {a} directly calls ({len(results)} total:)")
            print_list("direct callers", results)
        else:
            print(" Unknown command or wrong number of arguments. Type a command from list above.")

        print()


#
#   CLI Entry Point
#

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="InfraPy Call Graph Query System")
    parser.add_argument("--db", default="analysis_results.db", help="Path to SQLite database")
    parser.add_argument("--interactive", action="store_true", help="Launch interactive shell")
    parser.add_argument("--query", choices=["is_caller", "path", "callees", "callers", "direct", "who_calls"])
    parser.add_argument("--from", dest="func_from", help="Source function")
    parser.add_argument("--to", dest="func_to", help="Target function")
    parser.add_argument("--of", dest="func_of", help="Function to look up callers/callees of")
    args = parser.parse_args()

    forward, reverse = load_call_graph(args.db)

    if args.interactive or not args.query:
        interactive_shell(args.db)

    elif args.query == "is_caller":
        found, path = is_caller(forward, args.func_from, args.func_to)
        print(f"\n{'YES' if found else 'NO'}: {args.func_from} {'is' if found else 'is not'} a caller of {args.func_to}")
        if found:
            print("Path: " + " ->".join(path))
    elif args.query == "path":
        path = shortest_path(forward, args.func_from, args.func_to)
        print("\nShortest path: " + (" -> ".join(path) if path else "No path found"))

    elif args.query == "callees":
        results = all_callees(forward, args.func_from or args.func_of)
        print(f"\nAll reachable from {args.func_from or args.func_of}:")
        print_list("callees", results)

    elif args.query == "callers":
        results = all_callers(forward, args.func_of or args.func_to)
        print(f"\nAll callers of {args.func_of or args.func_to}:")
        print_list("callers", results)

    elif args.query == "direct":
        results = direct_callees(forward, args.func_from or args.func_of)
        print(f"\nDirect callees of {args.func_from or args.func_of}:")
        print_list("direct callees", results)

    elif args.query == "who_calls":
        results = direct_callers(forward, args.func_of or args.func_to)
        print(f"\nDirect callers of {args.func_of or args.func_to}:")
        print_list("direct callers", results)

        
