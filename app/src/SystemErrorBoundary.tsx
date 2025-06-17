import { Component, ErrorInfo, ReactNode } from 'react';
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { ChevronDown } from "lucide-react";

interface ErrorBoundaryProps {
  fallback?: ReactNode;
  children: ReactNode;
  viewName: string;
}

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
}

class SystemErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = { 
      hasError: false, 
      error: null,
      errorInfo: null
    };
  }
  
  get viewName() {
    return this.props.viewName.replace("Router", "");
  }

  static getDerivedStateFromError(error: Error): Partial<ErrorBoundaryState> {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo): void {
    this.setState({ errorInfo });
  }

  get isIframed() {
    return window !== window.parent;
  }

  componentDidMount() {
    window.addEventListener("error", this.handleGlobalError);
    window.addEventListener("unhandledrejection", this.handlePromiseRejection);
  }

  componentWillUnmount() {
    window.removeEventListener("error", this.handleGlobalError);
    window.removeEventListener("unhandledrejection", this.handlePromiseRejection);
  }

  handleGlobalError = (event: ErrorEvent) => {
    const error = event.error || new Error(event.message);
    if (!error.stack?.includes(this.viewName)) {
      return;
    }

    if (!this.state.hasError) {
      this.setState({
        hasError: true,
        error,
        errorInfo: { componentStack: "" } as ErrorInfo,
      });
    }
  };

  handlePromiseRejection = (event: PromiseRejectionEvent) => {
    const error = event.reason instanceof Error ? event.reason : new Error(String(event.reason));
    if (!error.stack?.includes(this.viewName)) {
      return;
    }

    if (!this.state.hasError) {
      this.setState({
        hasError: true,
        error,
        errorInfo: { componentStack: "" } as ErrorInfo,
      });
    }
  };

  handleFix = () => {
    const errorText = `Error: ${this.state.error?.message || "Unknown error"}\n\n${
      this.state.error?.stack || ""
    }

Component Stack: ${this.state.errorInfo?.componentStack || ""}`;
    
    if (this.isIframed) {
      window.parent?.postMessage({
        type: "fix-frontend-error",
        data: {
          viewName: this.viewName,
          errorText
        }
      }, "https://solarapp.dev")
    } else {
      navigator.clipboard.writeText(errorText)
    }
  };

  render(): ReactNode {
    if (this.state.hasError) {
      const isDynamicImportError = this.state.error?.message?.includes("Failed to fetch dynamically imported module");
      
      if (isDynamicImportError) {
        return (
          <div className="fixed inset-0 bg-background/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
            <Card className="w-full max-w-xl">
              <CardHeader>
                <CardTitle className="text-destructive text-2xl">Build Error</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="bg-muted p-4 rounded-md border-l-4 border-destructive text-base">
                  This view failed to build. Please click reload app to see a detailed fix bug message.
                </div>
              </CardContent>
              <CardFooter className="flex justify-center space-x-2">
              </CardFooter>
            </Card>
          </div>
        );
      }
      
      return this.props.fallback || (
        <div className="fixed inset-0 bg-background/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <Card className="w-full max-w-xl">
            <CardHeader>
              <CardTitle className="text-destructive text-2xl">Oops, we ran into an issue..</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="bg-muted p-4 rounded-md border-l-4 border-destructive text-base">
                {this.state.error?.message || 'Unknown error'}
              </div>
              
              <Collapsible>
                <CollapsibleTrigger asChild>
                  <Button variant="outline" className="w-full justify-between">
                    Show error details
                    <ChevronDown className="h-4 w-4" />
                  </Button>
                </CollapsibleTrigger>
                <CollapsibleContent>
                  <div className="bg-muted/50 p-4 mt-2 rounded-md font-mono text-sm whitespace-pre-wrap">
                    {this.state.error?.stack || ''}
                    {this.state.errorInfo?.componentStack && (
                      <>
                        {'Component Stack:'}
                        {this.state.errorInfo.componentStack}
                      </>
                    )}
                  </div>
                </CollapsibleContent>
              </Collapsible>
            </CardContent>
            <CardFooter className="flex justify-center space-x-2">
              <Button 
                onClick={this.handleFix}
                className="text-base py-2 px-4"
              >
                {this.isIframed ? "Fix with Flare" : "Copy error"}
              </Button>
            </CardFooter>
          </Card>
        </div>
      );
    }

    return this.props.children;
  }
}

export default SystemErrorBoundary;
