/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package ghidrachatgpt;

import com.theokanning.openai.completion.chat.ChatCompletionRequest;
import com.theokanning.openai.completion.chat.ChatMessage;
import com.theokanning.openai.completion.chat.ChatMessageRole;
import com.theokanning.openai.service.OpenAiService;
import ghidra.app.CorePluginPackage;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.flatapi.FlatDecompilerAPI;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import ghidra.util.task.TaskMonitor;
import java.lang.reflect.Method;
import java.time.Duration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import org.json.JSONObject;
import ghidra.framework.plugintool.PluginInfo;


//@formatter:off
@PluginInfo(status = PluginStatus.RELEASED,
            packageName = CorePluginPackage.NAME,
            category = PluginCategoryNames.ANALYSIS,
            shortDescription = "ChatGPT Plugin for Ghidra",
            description = "Brings the power of ChatGPT to Ghidra!",
            servicesRequired = {ConsoleService.class, CodeViewerService.class})
//@formatter:on
public class GhidraChatGPTPlugin extends ProgramPlugin {
  private ConsoleService cs;
  private CodeViewerService cvs;
  private GhidraChatGPTComponent uiComponent;
  private String apiToken;
  private String openAiModel = "gpt-3.5-turbo";
  private static final int OPENAI_TIMEOUT = 120;

  private static final String GCG_IDENTIFY_STRING =
      "Describe the function with as much detail as possible and include a link to an open source version if there is one\n %s";
  private static final String GCG_VULNERABILITY_STRING =
      "Describe all vulnerabilities in this function with as much detail as possible\n %s";
  private static final String GCG_BEAUTIFY_STRING =
      "For the following decompiled function, suggest a descriptive name for the function and for _every_ parameter and local variable (including names like local_18, local_res20, etc.). " +
      "Output only a JSON object whose keys are the original variable names and whose values are your suggested names. " +
      "Do not include any Markdown syntax such as ``` or additional commentary—just the raw JSON.\n\n%s";

  /**
   * Plugin constructor.
   */
  public GhidraChatGPTPlugin(PluginTool tool) {
    super(tool);

    uiComponent = new GhidraChatGPTComponent(this, getName());
    uiComponent.setHelpLocation(new HelpLocation(getClass().getPackage().getName(), "HelpAnchor"));
  }

  /* ------------------------------------------------------------------------- */
  /*                             Utility helpers                               */
  /* ------------------------------------------------------------------------- */

  /** Replace whitespace, leading digits, illegal chars. Return null if invalid. */
  private static String clean(String proposed) {
    proposed = proposed.trim().replaceAll("\\s+", "_");
    if (!proposed.isEmpty() && Character.isDigit(proposed.charAt(0))) {
      proposed = "_" + proposed;
    }
    return SymbolUtilities.containsInvalidChars(proposed) ? null : proposed;
  }

  private static String censorToken(String token) {
    return token.substring(0, 2) + "*".repeat(Math.max(0, token.length() - 2));
  }

  private static void endTx(Program p, int id, boolean commit) {
    try {
      Method m = Program.class.getMethod("endTransaction", int.class, boolean.class);
      m.invoke(p, id, commit); // works for both old and new API variants
    }
    catch (Exception ex) {
      throw new RuntimeException("Unable to end transaction", ex);
    }
  }

  /* ------------------------------------------------------------------------- */
  /*                                Lifecycle                                  */
  /* ------------------------------------------------------------------------- */

  @Override
  public void init() {
    super.init();
    cs  = tool.getService(ConsoleService.class);
    cvs = tool.getService(CodeViewerService.class);

    apiToken = System.getenv("OPENAI_TOKEN");
    if (apiToken != null) {
      ok(String.format("Loaded OpenAI Token: %s", censorToken(apiToken)));
    }
    ok("Default model is: " + openAiModel);
  }

  public void setModel(String model) { this.openAiModel = model; }
  public String getToken() { return apiToken; }
  public boolean setToken(String token) { if (token == null) return false; this.apiToken = token; return true; }

  /* ------------------------------------------------------------------------- */
  /*                           Menu/Action Handlers                            */
  /* ------------------------------------------------------------------------- */

  public void identifyFunction() {
    DecompilerResults dec = decompileCurrentFunc();
    if (dec == null) return;

    log("Identifying the current function: " + dec.func.getName());
    String res = askChatGPT(String.format(GCG_IDENTIFY_STRING, dec.decompiledFunc));
    if (res != null) {
      addComment(dec.prog, dec.func, res, "[GhidraChatGPT] - Identify Function");
    }
  }

  public void findVulnerabilities() {
    DecompilerResults dec = decompileCurrentFunc();
    if (dec == null) return;

    log("Finding vulnerabilities in the current function: " + dec.func.getName());
    String res = askChatGPT(String.format(GCG_VULNERABILITY_STRING, dec.decompiledFunc));
    if (res != null) {
      addComment(dec.prog, dec.func, res, "[GhidraChatGPT] - Find Vulnerabilities");
    }
  }

  public void beautifyFunction() {
    DecompilerResults dec = decompileCurrentFunc();
    if (dec == null) return;

    log("Beautifying the function: " + dec.func.getName());
    String res = askChatGPT(String.format(GCG_BEAUTIFY_STRING, dec.decompiledFunc));
    if (res != null) {
      updateVariables(dec.prog, dec, res);
      ok("Beautified the function: " + dec.func.getName());
    }
  }

  /* ------------------------------------------------------------------------- */
  /*                               Core logic                                  */
  /* ------------------------------------------------------------------------- */

  /**
   * Add a ChatGPT answer as a pre‑pended repeatable comment on the given function.
   */
  private void addComment(Program prog, Function func, String body, String header) {
    int tx = prog.startTransaction("GhidraChatGPT");
    try {
      String cur = func.getComment();
      String newComment = (cur == null || cur.isBlank()) ?
              header + "\n" + body :
              header + "\n" + body + "\n\n" + cur;
      func.setComment(newComment);
      ok("Added ChatGPT response as comment to function: " + func.getName());
    } finally {
      endTx(prog, tx, true);
    }
  }

  /* ------------------------------------------------------------------------- */
  /*                               Core logic                                  */
  /* ------------------------------------------------------------------------- */

  private static class DecompilerResults {
    final Program prog;
    final Function func;
    final String  decompiledFunc;
    DecompilerResults(Program p, Function f, String code) { this.prog = p; this.func = f; this.decompiledFunc = code; }
  }

  private DecompilerResults decompileCurrentFunc() {
    ProgramLocation loc = cvs.getCurrentLocation();
    if (loc == null) { error("No location in viewer"); return null; }

    Program prog = loc.getProgram();
    FlatProgramAPI fapi = new FlatProgramAPI(prog);
    Function func = fapi.getFunctionContaining(loc.getAddress());
    if (func == null) { error("Failed to find the current function"); return null; }

    FlatDecompilerAPI decAPI = new FlatDecompilerAPI(fapi);
    try {
      String code = decAPI.decompile(func);
      return new DecompilerResults(prog, func, code);
    }
    catch (Exception e) {
      error("Failed to decompile function " + func.getName() + ": " + e);
      return null;
    }
  }

  /**
   * Rename stack/param vars, SSA temps, **and the function itself** using ChatGPT JSON.
   */
  private void updateVariables(Program prog, DecompilerResults decRes, String jsonText) {
  
      /* ---------- parse JSON ---------- */
      JSONObject obj;
      try {
          log(jsonText);
          obj = new JSONObject(jsonText);
      } catch (Exception e) {
          error("Failed to parse beautify JSON");
          return;
      }
  
      /* ---------- begin Tx ---------- */
      Set<String> renamed = new HashSet<>();
      int tx = prog.startTransaction("GhidraChatGPT");
  
      /* ---------- pass #1 – normal variables (stack / params) ---------- */
      Variable[] vars = decRes.func.getAllVariables();
      if (vars != null) {
          for (Variable v : vars) {
              String old = v.getName();
              if (!obj.has(old)) {
                  continue;
              }
              String cleaned = clean(obj.getString(old));
              if (cleaned == null) {
                  error("Skipped invalid name: " + obj.getString(old));
                  continue;
              }
              try {
                  v.setName(cleaned, SourceType.USER_DEFINED);
                  ok(String.format("Beautified %s => %s", old, cleaned));
                  renamed.add(old);
              } catch (Exception ex) {
                  error("Failed to beautify " + old + " => " + cleaned);
              }
          }
      }
  
      /* ---------- pass #2 – SSA / high symbols ---------- */
      try {
          DecompInterface ifc = new DecompInterface();
          ifc.openProgram(prog);
          ifc.setSimplificationStyle("decompile");
          DecompileResults dRes =
              ifc.decompileFunction(decRes.func, 30, TaskMonitor.DUMMY);
          HighFunction hf = dRes.getHighFunction();
          if (hf != null) {
              LocalSymbolMap lsm = hf.getLocalSymbolMap();
              for (Iterator<HighSymbol> it = lsm.getSymbols(); it.hasNext();) {
                  HighSymbol hs = it.next();
                  String old = hs.getName();
                  if (renamed.contains(old) || !obj.has(old)) {
                      continue;
                  }
                  String cleaned = clean(obj.getString(old));
                  if (cleaned == null) {
                      continue;
                  }
                  try {
                      DataType dt = hs.getDataType();
                      HighFunctionDBUtil.updateDBVariable(
                          hs, cleaned, dt, SourceType.USER_DEFINED);
                      ok(String.format("Beautified (high) %s => %s", old, cleaned));
                      renamed.add(old);
                  } catch (Exception ex) {
                      error("Failed (high) to beautify " + old + " => " + cleaned);
                  }
              }
          }
          ifc.dispose();
      } catch (Exception ex) {
          error("High-level rename failed: " + ex.getMessage());
      }
  
      /* ---------- pass #3 – function name ---------- */
      String funcOld = decRes.func.getName();
  
      // ❶ direct key match
      if (obj.has(funcOld)) {
          String cleaned = clean(obj.getString(funcOld));
          if (cleaned != null) {
              try {
                  decRes.func.setName(cleaned, SourceType.USER_DEFINED);
                  ok(String.format("Beautified %s => %s", funcOld, cleaned));
              } catch (Exception ex) {
                  error("Failed to beautify function name " + funcOld +
                        " => " + cleaned);
              }
          }
      }
      // ❷ fallback: exactly one JSON entry left unprocessed – assume it’s the function
      else {
          Set<String> remaining = new HashSet<>(obj.keySet());
          remaining.removeAll(renamed);
          if (remaining.size() == 1) {
              String key     = remaining.iterator().next();   // original function name?
              String cleaned = clean(obj.getString(key));      // proposed new name
              if (cleaned != null) {
                  try {
                      decRes.func.setName(cleaned, SourceType.USER_DEFINED);
                      ok(String.format("Beautified %s => %s", funcOld, cleaned));
                  } catch (Exception ex) {
                      error("Failed (fallback) to beautify function name " +
                            funcOld + " => " + cleaned);
                  }
              }
          }
      }
  
      /* ---------- end Tx ---------- */
      endTx(prog, tx, true);
  }

  /* ------------------------------------------------------------------------- */
  /*                               ChatGPT I/O                                 */
  /* ------------------------------------------------------------------------- */

  private boolean ensureToken() {
    if (apiToken != null) return true;
    if (!setToken(uiComponent.askForOpenAIToken())) {
      error("Failed to update the OpenAI API token");
      return false;
    }
    return true;
  }

  private String askChatGPT(String prompt) {
    String resp = sendOpenAIRequest(prompt);
    if (resp == null) {
      error("The ChatGPT response was empty, try again!");
    }
    return resp;
  }

  private String sendOpenAIRequest(String prompt) {
    if (!ensureToken()) return null;

    OpenAiService svc = new OpenAiService(apiToken, Duration.ofSeconds(OPENAI_TIMEOUT));
    ChatCompletionRequest req = ChatCompletionRequest.builder()
        .model(openAiModel)
        .temperature(0.8)
        .messages(List.of(
            new ChatMessage(ChatMessageRole.SYSTEM.value(),
                "You are an assistant helping out with reverse engineering and vulnerability research"),
            new ChatMessage(ChatMessageRole.USER.value(), prompt)))
        .build();

    try {
      StringBuilder sb = new StringBuilder();
      svc.createChatCompletion(req).getChoices().forEach(c -> sb.append(c.getMessage().getContent()));
      return sb.toString();
    } catch (Exception e) {
      error("Asking ChatGPT failed: " + e);
      return null;
    }
  }

  /* ------------------------------------------------------------------------- */
  /*                               Logging helpers                             */
  /* ------------------------------------------------------------------------- */
  public void log(String msg)   { cs.println(getName() + " [>] " + msg); }
  public void ok(String msg)    { cs.println(getName() + " [+] " + msg); }
  public void error(String msg) { cs.println(getName() + " [-] " + msg); }
}

